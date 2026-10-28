#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <locale>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <windows.h>

namespace pe {
struct Error : std::runtime_error {
    using runtime_error::runtime_error;
};
struct Section {
    std::string name;
    uint32_t rva{}, virtualSize{}, rawOffset{}, rawSize{}, flags{};
};
struct Import {
    std::string library, name;
    uint16_t hint{};
    bool ordinal{}, delayed{};
};
struct Export {
    std::string name, forwarder;
    uint32_t ordinal{}, rva{};
};
struct Dependency {
    std::string name;
    size_t symbolCount{};
    bool delayed{};
};
struct Image {
    std::filesystem::path path;
    uint64_t fileSize{}, imageBase{};
    uint32_t entryPoint{}, imageSize{}, timestamp{}, checksum{};
    uint16_t machine{}, subsystem{}, characteristics{}, dllCharacteristics{};
    uint8_t linkerMajor{}, linkerMinor{};
    bool is64{}, managed{}, certificatePresent{};
    std::string sha256;
    std::vector<Section> sections;
    std::vector<Import> imports;
    std::vector<Export> exports;
    std::vector<Dependency> dependencies;
    std::vector<std::string> warnings;
    size_t libraryCount() const {
        std::set<std::string> libs;
        for (const auto& dependency : dependencies) {
            auto name = dependency.name;
            std::transform(name.begin(), name.end(), name.begin(),
                           [](unsigned char c) { return char(std::tolower(c)); });
            libs.insert(std::move(name));
        }
        if (!dependencies.empty())
            return libs.size();
        for (const auto& x : imports) {
            auto n = x.library;
            std::transform(n.begin(), n.end(), n.begin(),
                           [](unsigned char c) { return char(std::tolower(c)); });
            libs.insert(n);
        }
        return libs.size();
    }
    std::string architecture() const {
        switch (machine) {
        case IMAGE_FILE_MACHINE_AMD64:
            return "x64";
        case IMAGE_FILE_MACHINE_I386:
            return "x86";
        case IMAGE_FILE_MACHINE_ARM64:
            return "ARM64";
        case 0xA641:
            return "ARM64EC";
        case 0xA64E:
            return "ARM64X";
        case IMAGE_FILE_MACHINE_ARMNT:
            return "ARM";
        case IMAGE_FILE_MACHINE_IA64:
            return "IA-64";
        default:
            return "Unknown (" + hex(machine, 4) + ")";
        }
    }
    static std::string hex(uint64_t n, int width = 8) {
        std::ostringstream s;
        s.imbue(std::locale::classic());
        s << "0x" << std::uppercase << std::hex << std::setfill('0') << std::setw(width) << n;
        return s.str();
    }
    std::string subsystemName() const {
        switch (subsystem) {
        case 1:
            return "Native";
        case 2:
            return "Windows GUI";
        case 3:
            return "Windows Console";
        case 7:
            return "POSIX Console";
        case 9:
            return "Windows CE";
        case 10:
            return "EFI Application";
        case 11:
            return "EFI Boot Driver";
        case 12:
            return "EFI Runtime Driver";
        case 14:
            return "Xbox";
        case 16:
            return "Windows Boot";
        default:
            return "Unknown (" + std::to_string(subsystem) + ")";
        }
    }
};

struct Cancellation {
    const std::atomic_bool* flag{};
    void check() const;
};
struct Cancelled : Error {
    Cancelled() : Error("Inspection cancelled.") {}
};
inline constexpr const char* Version = "1.1.0";
std::string utf8(const std::wstring& text);
std::wstring wide(const std::string& text);
std::string hash(const std::vector<uint8_t>& bytes, Cancellation cancel = {});
Image parseBytes(const std::vector<uint8_t>& bytes, Cancellation cancel = {});
Image load(const std::filesystem::path& path, Cancellation cancel = {});
std::string jsonEscape(const std::string& text);
std::string jsonUtf8(const std::string& text);
std::string json(const Image& image);
std::wstring report(const Image& image);
void writeReport(const std::filesystem::path& target, const std::string& content,
                 const std::filesystem::path& protectedInput = {});
class Reader {
  public:
    explicit Reader(const std::vector<uint8_t>& bytes) : bytes_(bytes) {}
    Image parse() const {
        return parseBytes(bytes_);
    }

  private:
    const std::vector<uint8_t>& bytes_;
};
} // namespace pe
