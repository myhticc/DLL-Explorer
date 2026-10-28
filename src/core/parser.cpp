#include "../pe.hpp"
#include <array>
#include <bcrypt.h>
#include <cstring>
#include <map>
#include <type_traits>
namespace pe {
std::string hash(const std::vector<uint8_t>& bytes, Cancellation cancel) {
    struct Algorithm {
        BCRYPT_ALG_HANDLE value{};
        ~Algorithm() {
            if (value)
                BCryptCloseAlgorithmProvider(value, 0);
        }
    } algorithm;
    cancel.check();
    if (BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw Error("SHA-256 is unavailable.");
    DWORD objectSize = 0, received = 0;
    if (BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &received,
                          0) < 0)
        throw Error("SHA-256 could not be initialized.");
    std::vector<uint8_t> object(objectSize);
    struct Hash {
        BCRYPT_HASH_HANDLE value{};
        ~Hash() {
            if (value)
                BCryptDestroyHash(value);
        }
    } state;
    if (BCryptCreateHash(algorithm.value, &state.value, object.data(), objectSize, nullptr, 0, 0) <
        0)
        throw Error("SHA-256 could not be initialized.");
    constexpr size_t chunkSize = 1024 * 1024;
    for (size_t offset = 0; offset < bytes.size();) {
        cancel.check();
        const auto count = ULONG(std::min(chunkSize, bytes.size() - offset));
        if (BCryptHashData(state.value, const_cast<PUCHAR>(bytes.data() + offset), count, 0) < 0)
            throw Error("SHA-256 could not be calculated.");
        offset += count;
    }
    cancel.check();
    std::array<uint8_t, 32> digest{};
    if (BCryptFinishHash(state.value, digest.data(), ULONG(digest.size()), 0) < 0)
        throw Error("SHA-256 could not be calculated.");
    std::ostringstream result;
    result.imbue(std::locale::classic());
    for (auto byte : digest)
        result << std::hex << std::setfill('0') << std::setw(2) << int(byte);
    return result.str();
}

class Parser {
    const std::vector<uint8_t>& b;
    Cancellation cancel;
    Image out;
    uint32_t headerSize{};
    std::array<IMAGE_DATA_DIRECTORY, 16> directories{};
    static constexpr size_t maxSymbols = 250000;
    mutable size_t stringBytes{};
    void accountString(size_t n) const {
        constexpr size_t budget = 64 * 1024 * 1024;
        if (n > budget - stringBytes)
            throw Error("Symbol text limit reached (64 MB).");
        stringBytes += n;
    }
    template <class T> T read(uint64_t offset) const {
        static_assert(std::is_trivially_copyable_v<T>, "PE fields must be trivially copyable.");
        cancel.check();
        if (offset > b.size() || sizeof(T) > b.size() - size_t(offset))
            throw Error("The file is truncated or contains an invalid offset.");
        T v;
        memcpy(&v, b.data() + size_t(offset), sizeof(v));
        return v;
    }
    size_t rva(uint64_t address, size_t length = 1) const {
        if (address == 0)
            throw Error("A required PE address is null.");
        if (address > UINT32_MAX)
            throw Error("An address exceeds the PE address range.");
        if (address < headerSize && length <= uint64_t(headerSize) - address &&
            address <= b.size() && length <= b.size() - size_t(address))
            return size_t(address);
        for (const auto& s : out.sections) {
            if (address >= s.rva) {
                uint64_t delta = address - s.rva;
                if (delta < s.rawSize && length <= uint64_t(s.rawSize) - delta) {
                    uint64_t offset = uint64_t(s.rawOffset) + delta;
                    if (offset <= b.size() && length <= b.size() - size_t(offset))
                        return size_t(offset);
                }
            }
        }
        throw Error("An RVA points outside the file-backed sections.");
    }
    template <class T> T at(uint64_t address) const {
        return read<T>(rva(address, sizeof(T)));
    }
    std::string str(uint64_t address, size_t maximumLength = 32768) const {
        size_t start = rva(address), cap = 0;
        if (address < headerSize)
            cap = size_t(headerSize - address);
        else
            for (const auto& s : out.sections)
                if (address >= s.rva && address - uint64_t(s.rva) < s.rawSize) {
                    cap = size_t(s.rawSize - (address - s.rva));
                    break;
                }
        cap = std::min({cap, b.size() - start, maximumLength});
        for (size_t n = 0; n < cap; n++)
            if (b[start + n] == 0) {
                accountString(n);
                return std::string(reinterpret_cast<const char*>(b.data() + start), n);
            }
        throw Error("A PE string has no valid terminator.");
    }
    void warn(const std::string& context, const std::string& message) {
        out.warnings.push_back(context + ": " + message);
    }
    void thunks(uint32_t table, const std::string& lib, bool delayed, bool legacyVa = false) {
        if (!table)
            return;
        uint64_t step = out.is64 ? 8 : 4;
        for (size_t i = 0; i < maxSymbols; i++) {
            uint64_t value = out.is64 ? at<uint64_t>(uint64_t(table) + i * step)
                                      : at<uint32_t>(uint64_t(table) + i * step);
            if (!value)
                return;
            if (out.imports.size() >= maxSymbols)
                throw Error("Import limit reached (250,000 symbols).");
            accountString(lib.size());
            Import item;
            item.library = lib;
            item.delayed = delayed;
            uint64_t mask = out.is64 ? 0x8000000000000000ULL : 0x80000000ULL;
            if (value & mask) {
                item.ordinal = true;
                item.hint = uint16_t(value);
                item.name = "#" + std::to_string(item.hint);
            } else {
                if (legacyVa) {
                    if (value < out.imageBase)
                        throw Error("A delay-import name has an invalid VA.");
                    value -= out.imageBase;
                }
                item.hint = at<uint16_t>(value);
                item.name = str(value + 2);
            }
            out.imports.push_back(std::move(item));
        }
        throw Error("Import table has no valid terminator.");
    }
    void imports() {
        auto d = directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!d.VirtualAddress && !d.Size)
            return;
        if (!d.VirtualAddress || d.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR))
            throw Error("Invalid import directory size or address.");
        size_t count = std::min<size_t>(d.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR), 4096);
        for (size_t i = 0; i < count; i++) {
            auto desc = at<IMAGE_IMPORT_DESCRIPTOR>(uint64_t(d.VirtualAddress) +
                                                    i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
            if (!desc.OriginalFirstThunk && !desc.FirstThunk && !desc.Name && !desc.TimeDateStamp &&
                !desc.ForwarderChain)
                return;
            auto name = str(desc.Name);
            if (name.empty())
                throw Error("An import descriptor has an empty library name.");
            const size_t firstSymbol = out.imports.size();
            out.dependencies.push_back({name, 0, false});
            try {
                thunks(desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk, name,
                       false);
            } catch (const Cancelled&) {
                throw;
            } catch (const Error& e) {
                warn("Imports in " + name, e.what());
            }
            out.dependencies.back().symbolCount = out.imports.size() - firstSymbol;
        }
        throw Error("Import directory has no valid terminator or is too large.");
    }
    void delayedImports() {
        auto d = directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        if (!d.VirtualAddress && !d.Size)
            return;
        struct Delay {
            uint32_t attr, name, handle, iat, intable, bound, unload, time;
        };
        if (!d.VirtualAddress || d.Size < sizeof(Delay))
            throw Error("Invalid delay import directory size or address.");
        size_t count = std::min<size_t>(d.Size / sizeof(Delay), 4096);
        for (size_t i = 0; i < count; i++) {
            auto x = at<Delay>(uint64_t(d.VirtualAddress) + i * sizeof(Delay));
            if (!x.attr && !x.name && !x.handle && !x.iat && !x.intable && !x.bound && !x.unload &&
                !x.time)
                return;
            auto addr = [&](uint32_t v) -> uint32_t {
                if (!v)
                    return 0;
                if (x.attr & 1)
                    return v;
                if (uint64_t(v) < out.imageBase || uint64_t(v) - out.imageBase > UINT32_MAX)
                    throw Error("Invalid delay-load VA.");
                return uint32_t(uint64_t(v) - out.imageBase);
            };
            auto name = str(addr(x.name));
            if (name.empty())
                throw Error("A delay import descriptor has an empty library name.");
            const size_t firstSymbol = out.imports.size();
            out.dependencies.push_back({name, 0, true});
            try {
                thunks(addr(x.intable ? x.intable : x.iat), name, true, (x.attr & 1) == 0);
            } catch (const Cancelled&) {
                throw;
            } catch (const Error& e) {
                warn("Delay imports in " + name, e.what());
            }
            out.dependencies.back().symbolCount = out.imports.size() - firstSymbol;
        }
        throw Error("Delay import directory has no valid terminator or is too large.");
    }
    void exports() {
        auto d = directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!d.VirtualAddress && !d.Size)
            return;
        if (!d.VirtualAddress || d.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
            throw Error("Invalid export directory size or address.");
        auto desc = at<IMAGE_EXPORT_DIRECTORY>(d.VirtualAddress);
        if (desc.NumberOfFunctions > maxSymbols || desc.NumberOfNames > maxSymbols)
            throw Error("Export limit reached (250,000 symbols).");
        if (!desc.NumberOfFunctions) {
            if (desc.NumberOfNames)
                throw Error("Export names exist without a function table.");
            return;
        }
        rva(desc.AddressOfFunctions, size_t(desc.NumberOfFunctions) * 4);
        if (desc.NumberOfNames) {
            rva(desc.AddressOfNames, size_t(desc.NumberOfNames) * 4);
            rva(desc.AddressOfNameOrdinals, size_t(desc.NumberOfNames) * 2);
        }
        std::map<uint32_t, std::vector<std::string>> names;
        for (uint32_t i = 0; i < desc.NumberOfNames; i++) {
            auto index = at<uint16_t>(uint64_t(desc.AddressOfNameOrdinals) + uint64_t(i) * 2);
            if (index >= desc.NumberOfFunctions)
                throw Error("An export name references an invalid ordinal index.");
            names[index].push_back(
                str(at<uint32_t>(uint64_t(desc.AddressOfNames) + uint64_t(i) * 4)));
        }
        for (uint32_t i = 0; i < desc.NumberOfFunctions; i++) {
            auto address = at<uint32_t>(uint64_t(desc.AddressOfFunctions) + uint64_t(i) * 4);
            if (!address)
                continue;
            uint64_t ord = uint64_t(desc.Base) + i;
            if (ord > UINT32_MAX)
                throw Error("An export ordinal overflows.");
            std::string forward;
            if (address >= d.VirtualAddress &&
                uint64_t(address) < uint64_t(d.VirtualAddress) + d.Size)
                forward = str(address, size_t(uint64_t(d.VirtualAddress) + d.Size - address));
            auto found = names.find(i);
            const size_t count = found == names.end() ? 1 : found->second.size();
            if (count > maxSymbols - out.exports.size())
                throw Error("Export limit reached (250,000 symbols).");
            accountString(forward.size() * count);
            if (found == names.end())
                out.exports.push_back({"(ordinal only)", forward, uint32_t(ord), address});
            else
                for (auto& n : found->second)
                    out.exports.push_back({std::move(n), forward, uint32_t(ord), address});
        }
    }

  public:
    explicit Parser(const std::vector<uint8_t>& bytes, Cancellation cancellation)
        : b(bytes), cancel(cancellation) {}
    Image parse() {
        auto dos = read<IMAGE_DOS_HEADER>(0);
        if (dos.e_magic != IMAGE_DOS_SIGNATURE)
            throw Error("This is not a Windows PE file. Choose a DLL or EXE.");
        if (dos.e_lfanew < 64)
            throw Error("The PE header offset is invalid.");
        uint64_t nt = uint32_t(dos.e_lfanew);
        if (read<DWORD>(nt) != IMAGE_NT_SIGNATURE)
            throw Error("The Windows PE signature is missing.");
        auto file = read<IMAGE_FILE_HEADER>(nt + 4);
        if (!file.NumberOfSections || file.NumberOfSections > 96)
            throw Error("The section count is invalid (expected 1-96).");
        out.machine = file.Machine;
        out.timestamp = file.TimeDateStamp;
        out.characteristics = file.Characteristics;
        uint64_t opt = nt + 4 + sizeof(file);
        if (opt > b.size() || file.SizeOfOptionalHeader > b.size() - size_t(opt))
            throw Error("The optional header is truncated.");
        uint16_t magic = read<uint16_t>(opt);
        size_t dirOffset = 0;
        uint32_t nDirs = 0;
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            out.is64 = true;
            dirOffset = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
            if (file.SizeOfOptionalHeader < dirOffset)
                throw Error("The PE32+ optional header is incomplete.");
            IMAGE_OPTIONAL_HEADER64 o{};
            memcpy(&o, b.data() + opt, std::min<size_t>(sizeof(o), file.SizeOfOptionalHeader));
            out.imageBase = o.ImageBase;
            out.entryPoint = o.AddressOfEntryPoint;
            out.imageSize = o.SizeOfImage;
            out.subsystem = o.Subsystem;
            out.dllCharacteristics = o.DllCharacteristics;
            out.checksum = o.CheckSum;
            out.linkerMajor = o.MajorLinkerVersion;
            out.linkerMinor = o.MinorLinkerVersion;
            headerSize = o.SizeOfHeaders;
            nDirs = o.NumberOfRvaAndSizes;
        } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            dirOffset = offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
            if (file.SizeOfOptionalHeader < dirOffset)
                throw Error("The PE32 optional header is incomplete.");
            IMAGE_OPTIONAL_HEADER32 o{};
            memcpy(&o, b.data() + opt, std::min<size_t>(sizeof(o), file.SizeOfOptionalHeader));
            out.imageBase = o.ImageBase;
            out.entryPoint = o.AddressOfEntryPoint;
            out.imageSize = o.SizeOfImage;
            out.subsystem = o.Subsystem;
            out.dllCharacteristics = o.DllCharacteristics;
            out.checksum = o.CheckSum;
            out.linkerMajor = o.MajorLinkerVersion;
            out.linkerMinor = o.MinorLinkerVersion;
            headerSize = o.SizeOfHeaders;
            nDirs = o.NumberOfRvaAndSizes;
        } else
            throw Error("The optional header is not PE32 or PE32+.");
        if (headerSize > b.size())
            throw Error("The declared headers extend beyond the file.");
        const uint64_t sectionTableEnd =
            opt + file.SizeOfOptionalHeader +
            uint64_t(file.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        if (sectionTableEnd > headerSize)
            throw Error("The section table extends beyond the declared headers.");
        size_t available = (file.SizeOfOptionalHeader - dirOffset) / sizeof(IMAGE_DATA_DIRECTORY);
        if (nDirs > available)
            throw Error("The data directory count exceeds the optional header.");
        for (size_t i = 0; i < std::min<size_t>(nDirs, 16); i++)
            directories[i] = read<IMAGE_DATA_DIRECTORY>(opt + dirOffset + i * 8);
        for (size_t i = 0; i < file.NumberOfSections; i++) {
            auto s = read<IMAGE_SECTION_HEADER>(opt + file.SizeOfOptionalHeader +
                                                i * sizeof(IMAGE_SECTION_HEADER));
            size_t len = 0;
            while (len < 8 && s.Name[len])
                len++;
            if (s.SizeOfRawData && (s.PointerToRawData > b.size() ||
                                    s.SizeOfRawData > b.size() - size_t(s.PointerToRawData)))
                throw Error("A section extends beyond the end of the file.");
            out.sections.push_back({std::string(reinterpret_cast<char*>(s.Name), len),
                                    s.VirtualAddress, s.Misc.VirtualSize, s.PointerToRawData,
                                    s.SizeOfRawData, s.Characteristics});
        }
        out.fileSize = b.size();
        out.managed = directories[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0;
        auto cert = directories[IMAGE_DIRECTORY_ENTRY_SECURITY];
        out.certificatePresent = cert.VirtualAddress != 0 && cert.Size >= 8 &&
                                 cert.VirtualAddress <= b.size() &&
                                 cert.Size <= b.size() - cert.VirtualAddress;
        try {
            imports();
        } catch (const Cancelled&) {
            throw;
        } catch (const Error& e) {
            warn("Import directory", e.what());
        }
        try {
            delayedImports();
        } catch (const Cancelled&) {
            throw;
        } catch (const Error& e) {
            warn("Delay import directory", e.what());
        }
        try {
            exports();
        } catch (const Cancelled&) {
            throw;
        } catch (const Error& e) {
            warn("Export directory", e.what());
        }
        out.sha256 = hash(b, cancel);
        return std::move(out);
    }
};

Image parseBytes(const std::vector<uint8_t>& bytes, Cancellation cancel) {
    return Parser(bytes, cancel).parse();
}
} // namespace pe
