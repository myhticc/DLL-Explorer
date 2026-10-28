#include "../pe.hpp"
#include "resource.hpp"
#include <climits>

namespace pe {
namespace {
constexpr uint64_t maximumFileSize = 512ULL * 1024 * 1024;
constexpr DWORD ioChunkSize = 1024 * 1024;

std::string systemMessage(DWORD code) {
    wchar_t* message = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<LPWSTR>(&message), 0, nullptr);
    std::wstring text =
        length ? std::wstring(message, length) : L"Windows error " + std::to_wstring(code);
    if (message)
        LocalFree(message);
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' '))
        text.pop_back();
    return utf8(text);
}

[[noreturn]] void fail(const char* context) {
    const DWORD code = GetLastError();
    throw Error(std::string(context) + ": " + systemMessage(code));
}

bool sameFile(const std::filesystem::path& a, const std::filesystem::path& b) {
    if (a.empty() || b.empty())
        return false;
    std::error_code error;
    if (std::filesystem::equivalent(a, b, error) && !error)
        return true;
    const auto left = std::filesystem::absolute(a).lexically_normal().wstring();
    const auto right = std::filesystem::absolute(b).lexically_normal().wstring();
    return CompareStringOrdinal(left.c_str(), int(left.size()), right.c_str(), int(right.size()),
                                TRUE) == CSTR_EQUAL;
}
} // namespace

void Cancellation::check() const {
    if (flag && flag->load(std::memory_order_relaxed))
        throw Cancelled();
}

std::string utf8(const std::wstring& text) {
    if (text.empty())
        return {};
    if (text.size() > INT_MAX)
        throw Error("Text is too long to convert.");
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                                           int(text.size()), nullptr, 0, nullptr, nullptr);
    if (!length)
        fail("Could not encode Unicode text");
    std::string result(size_t(length), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), int(text.size()),
                             result.data(), length, nullptr, nullptr))
        fail("Could not encode Unicode text");
    return result;
}

std::wstring wide(const std::string& text) {
    if (text.empty())
        return {};
    if (text.size() > INT_MAX)
        throw Error("Text is too long to convert.");
    UINT codepage = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    int length = MultiByteToWideChar(codepage, flags, text.data(), int(text.size()), nullptr, 0);
    if (!length) {
        codepage = CP_ACP;
        flags = 0;
        length = MultiByteToWideChar(codepage, flags, text.data(), int(text.size()), nullptr, 0);
    }
    if (!length)
        fail("Could not decode text");
    std::wstring result(size_t(length), L'\0');
    if (!MultiByteToWideChar(codepage, flags, text.data(), int(text.size()), result.data(), length))
        fail("Could not decode text");
    return result;
}

Image load(const std::filesystem::path& path, Cancellation cancel) {
    cancel.check();
    // Deny concurrent writes while taking the snapshot. This keeps parsing and the
    // reported hash consistent, including for a file another process is rebuilding.
    platform::Handle file(CreateFileW(path.c_str(), GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                      FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!file)
        fail("Could not open the file");
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(file.get(), &length))
        fail("Could not read the file size");
    if (length.QuadPart < 0 || uint64_t(length.QuadPart) > maximumFileSize)
        throw Error("This file is larger than the 512 MB inspection limit.");

    std::vector<uint8_t> bytes(static_cast<size_t>(length.QuadPart));
    size_t position = 0;
    while (position < bytes.size()) {
        cancel.check();
        const DWORD requested = DWORD(std::min<size_t>(ioChunkSize, bytes.size() - position));
        DWORD received = 0;
        if (!ReadFile(file.get(), bytes.data() + position, requested, &received, nullptr))
            fail("Could not read the file");
        if (!received)
            throw Error("The file ended before its declared size.");
        position += received;
    }
    auto image = parseBytes(bytes, cancel);
    image.path = std::filesystem::absolute(path).lexically_normal();
    return image;
}

void writeReport(const std::filesystem::path& target, const std::string& content,
                 const std::filesystem::path& protectedInput) {
    if (sameFile(target, protectedInput))
        throw Error("Choose a different report path. The inspected binary cannot be overwritten.");

    const auto absolute = std::filesystem::absolute(target).lexically_normal();
    static std::atomic_uint64_t sequence{0};
    std::filesystem::path temporary;
    platform::Handle file;
    for (int attempt = 0; attempt < 32; ++attempt) {
        temporary = absolute.parent_path() /
                    (L".dllexplorer-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                     std::to_wstring(GetTickCount64()) + L"-" +
                     std::to_wstring(sequence.fetch_add(1, std::memory_order_relaxed)) + L".tmp");
        file.reset(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                               FILE_ATTRIBUTE_NORMAL, nullptr));
        if (file)
            break;
        if (GetLastError() != ERROR_FILE_EXISTS)
            fail("Could not create the report");
    }
    if (!file)
        throw Error("Could not create a temporary report file.");

    // A failed write must leave any previous report intact.
    struct Cleanup {
        std::filesystem::path path;
        bool committed = false;
        ~Cleanup() {
            if (!committed)
                DeleteFileW(path.c_str());
        }
    } cleanup{temporary};
    try {
        size_t position = 0;
        while (position < content.size()) {
            const DWORD requested = DWORD(std::min<size_t>(ioChunkSize, content.size() - position));
            DWORD written = 0;
            if (!WriteFile(file.get(), content.data() + position, requested, &written, nullptr))
                fail("Could not write the report");
            if (!written)
                throw Error("The report write made no progress.");
            position += written;
        }
        if (!FlushFileBuffers(file.get()))
            fail("Could not finish writing the report");
        file.reset();
        if (!MoveFileExW(temporary.c_str(), absolute.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            fail("Could not replace the report");
        cleanup.committed = true;
    } catch (...) {
        file.reset(); // Close before Cleanup tries to remove the temporary file.
        throw;
    }
}
} // namespace pe
