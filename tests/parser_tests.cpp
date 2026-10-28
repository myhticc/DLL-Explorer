#include "../src/pe.hpp"
#include <cstring>
#include <iostream>
#include <random>
#pragma comment(lib, "bcrypt.lib")
int checks = 0;
void check(bool condition, const char* message) {
    checks++;
    if (!condition)
        throw std::runtime_error(message);
}
template <class T> void put(std::vector<uint8_t>& b, size_t offset, const T& v) {
    memcpy(b.data() + offset, &v, sizeof(v));
}
size_t raw(uint32_t rva) {
    return size_t(rva) - 0x1000 + 0x200;
}
void stringAt(std::vector<uint8_t>& b, uint32_t rva, const char* s) {
    memcpy(b.data() + raw(rva), s, strlen(s) + 1);
}
std::vector<uint8_t> fixture(bool x64) {
    std::vector<uint8_t> b(0x1400);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    put(b, 0, dos);
    put(b, 0x80, DWORD(IMAGE_NT_SIGNATURE));
    IMAGE_FILE_HEADER f{};
    f.Machine = x64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    f.NumberOfSections = 1;
    f.Characteristics = IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE;
    f.SizeOfOptionalHeader =
        x64 ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32);
    put(b, 0x84, f);
    IMAGE_DATA_DIRECTORY exp{0x1100, 0x100}, imp{0x1300, 40}, delay{0x1500, 64};
    if (x64) {
        IMAGE_OPTIONAL_HEADER64 o{};
        o.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        o.ImageBase = 0x180000000;
        o.SizeOfHeaders = 0x200;
        o.SizeOfImage = 0x3000;
        o.NumberOfRvaAndSizes = 16;
        o.AddressOfEntryPoint = 0x1800;
        o.Subsystem = 2;
        o.DataDirectory[0] = exp;
        o.DataDirectory[1] = imp;
        o.DataDirectory[13] = delay;
        put(b, 0x98, o);
    } else {
        IMAGE_OPTIONAL_HEADER32 o{};
        o.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        o.ImageBase = 0x10000000;
        o.SizeOfHeaders = 0x200;
        o.SizeOfImage = 0x3000;
        o.NumberOfRvaAndSizes = 16;
        o.AddressOfEntryPoint = 0x1800;
        o.Subsystem = 2;
        o.DataDirectory[0] = exp;
        o.DataDirectory[1] = imp;
        o.DataDirectory[13] = delay;
        put(b, 0x98, o);
    }
    IMAGE_SECTION_HEADER sec{};
    memcpy(sec.Name, ".test", 5);
    sec.VirtualAddress = 0x1000;
    sec.Misc.VirtualSize = 0x1200;
    sec.PointerToRawData = 0x200;
    sec.SizeOfRawData = 0x1200;
    sec.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    put(b, 0x98 + f.SizeOfOptionalHeader, sec);
    IMAGE_EXPORT_DIRECTORY e{};
    e.Base = 7;
    e.NumberOfFunctions = 4;
    e.NumberOfNames = 2;
    e.AddressOfFunctions = 0x1140;
    e.AddressOfNames = 0x1150;
    e.AddressOfNameOrdinals = 0x1160;
    put(b, raw(0x1100), e);
    put(b, raw(0x1140), DWORD(0x1800));
    put(b, raw(0x1144), DWORD(0x11c0));
    put(b, raw(0x1148), DWORD(0x1810));
    put(b, raw(0x114c), DWORD(0));
    put(b, raw(0x1150), DWORD(0x1180));
    put(b, raw(0x1154), DWORD(0x1190));
    put(b, raw(0x1160), WORD(0));
    put(b, raw(0x1162), WORD(1));
    stringAt(b, 0x1180, "Hello");
    stringAt(b, 0x1190, "Forwarded");
    stringAt(b, 0x11c0, "KERNEL32.Sleep");
    IMAGE_IMPORT_DESCRIPTOR i{};
    i.OriginalFirstThunk = 0x1350;
    i.FirstThunk = 0x1350;
    i.Name = 0x1380;
    put(b, raw(0x1300), i);
    stringAt(b, 0x1380, "KERNEL32.dll");
    put(b, raw(0x13a0), WORD(42));
    stringAt(b, 0x13a2, "Sleep");
    if (x64) {
        put(b, raw(0x1350), uint64_t(0x13a0));
        put(b, raw(0x1358), uint64_t(0x800000000000000c));
    } else {
        put(b, raw(0x1350), uint32_t(0x13a0));
        put(b, raw(0x1354), uint32_t(0x8000000c));
    }
    struct Delay {
        uint32_t attr, name, handle, iat, intable, bound, unload, time;
    };
    Delay d{1, 0x1580, 0, 0x1550, 0x1550, 0, 0, 0};
    put(b, raw(0x1500), d);
    stringAt(b, 0x1580, "USER32.dll");
    put(b, raw(0x15a0), WORD(9));
    stringAt(b, 0x15a2, "MessageBoxW");
    if (x64) {
        put(b, raw(0x1550), uint64_t(0x15a0));
        put(b, raw(0x1558), uint64_t(0x8000000000000016));
    } else {
        put(b, raw(0x1550), uint32_t(0x15a0));
        put(b, raw(0x1554), uint32_t(0x80000016));
    }
    return b;
}
void rejects(const std::vector<uint8_t>& b) {
    bool thrown = false;
    try {
        pe::Reader(b).parse();
    } catch (const pe::Error&) {
        thrown = true;
    }
    check(thrown, "Malformed core headers must be rejected");
}
int main() {
    try {
        std::vector<uint8_t> abc{'a', 'b', 'c'};
        check(pe::hash(abc) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
              "SHA256 known answer");
        for (bool is64 : {false, true}) {
            auto b = fixture(is64);
            auto x = pe::Reader(b).parse();
            check(x.is64 == is64, "PE format");
            check(x.architecture() == (is64 ? "x64" : "x86"), "Architecture");
            check(x.sections.size() == 1, "Section count");
            check(x.warnings.empty(), "Valid fixture must have no warnings");
            check(x.imports.size() == 4, "Standard and delayed imports");
            check(x.libraryCount() == 2, "Dependency count");
            check(x.imports[0].name == "Sleep" && x.imports[0].hint == 42, "Named import");
            check(x.imports[1].ordinal && x.imports[1].name == "#12", "Ordinal import");
            check(x.imports[2].delayed && x.imports[2].name == "MessageBoxW", "Delay import");
            check(x.imports[3].delayed && x.imports[3].ordinal, "Delay ordinal");
            check(x.exports.size() == 3, "Sparse export table");
            check(x.exports[0].name == "Hello" && x.exports[0].ordinal == 7, "Named export");
            check(x.exports[1].forwarder == "KERNEL32.Sleep", "Forwarded export");
            check(x.exports[2].name == "(ordinal only)" && x.exports[2].ordinal == 9,
                  "Ordinal-only export");
            check(pe::json(x).find("\"delay_load\": true") != std::string::npos,
                  "JSON delay import");
            check(pe::report(x).find(L"EXPORTS (3)") != std::wstring::npos, "Text report");
            auto nullAddress = b;
            put(nullAddress, raw(0x1300) + 12, DWORD(0));
            check(!pe::Reader(nullAddress).parse().warnings.empty(),
                  "Null module name must not read DOS header bytes");
            nullAddress = b;
            put(nullAddress, raw(0x1100) + 28, DWORD(0));
            check(!pe::Reader(nullAddress).parse().warnings.empty(),
                  "Null export address table must produce a warning");
            nullAddress = b;
            put(nullAddress, raw(0x1100) + 32, DWORD(0));
            check(!pe::Reader(nullAddress).parse().warnings.empty(),
                  "Null export names table must produce a warning");
            auto controlled = x;
            controlled.exports[0].name = "name\nwith\ttabs";
            check(pe::report(controlled).find(L"name\\nwith\\ttabs") != std::wstring::npos,
                  "Control characters cannot inject text report rows");
            auto bad = b;
            put(bad, 0x80, DWORD(0));
            rejects(bad);
            bad = b;
            put(bad, 0x3c, LONG(-1));
            rejects(bad);
            bad = b;
            put(bad, 0x86, WORD(65535));
            rejects(bad);
            bad = b;
            put(bad, raw(0x1160), WORD(9));
            check(!pe::Reader(bad).parse().warnings.empty(),
                  "Invalid export index must produce warning");
            bad = b;
            put(bad, raw(0x1300) + 12, DWORD(0xfffffff0));
            check(!pe::Reader(bad).parse().warnings.empty(),
                  "Invalid import RVA must produce warning");
            bad = b;
            put(bad, raw(0x1100) + 20, DWORD(0xffffffff));
            check(!pe::Reader(bad).parse().warnings.empty(),
                  "Oversized export table must produce warning");
            bad = b;
            put(bad, raw(0x1300), DWORD(0));
            check(pe::Reader(bad).parse().imports.size() == 4, "FirstThunk fallback");
            bad = b;
            put(bad, raw(0x1300), DWORD(0));
            put(bad, raw(0x1300) + 16, DWORD(0));
            auto emptyDependency = pe::Reader(bad).parse();
            check(emptyDependency.libraryCount() == 2,
                  "Zero-symbol dependency must remain visible");
            check(emptyDependency.dependencies[0].symbolCount == 0,
                  "Empty library has zero symbols");
            check(emptyDependency.imports.size() == 2,
                  "Delay imports remain after empty standard imports");
            bad = b;
            const size_t dirs = 0x98 + (is64 ? offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory)
                                             : offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory));
            put(bad, dirs + 4, DWORD(4));
            check(!pe::Reader(bad).parse().warnings.empty(),
                  "Undersized export directory must produce a warning");
            bad = b;
            put(bad, raw(0x1144), DWORD(0x11ff));
            bad[raw(0x11ff)] = 'X';
            check(!pe::Reader(bad).parse().warnings.empty(),
                  "Forwarder cannot extend beyond the export directory");
            if (!is64) {
                bad = b;
                put(bad, raw(0x1500), DWORD(0));
                for (auto offset : {4, 12, 16}) {
                    DWORD address{};
                    memcpy(&address, bad.data() + raw(0x1500) + offset, 4);
                    put(bad, raw(0x1500) + offset, DWORD(address + 0x10000000));
                }
                put(bad, raw(0x1550), DWORD(0x100015a0));
                auto legacy = pe::Reader(bad).parse();
                check(legacy.warnings.empty() && legacy.imports.size() == 4,
                      "Legacy VA-based delay imports");
                check(legacy.imports[2].name == "MessageBoxW", "Legacy delay import name");
            }
            for (size_t size = 0; size < 0x200; size++) {
                auto truncated = b;
                truncated.resize(size);
                rejects(truncated);
            }
        }
        for (auto name :
             {L"C:\\Windows\\System32\\version.dll", L"C:\\Windows\\SysWOW64\\version.dll",
              L"C:\\Windows\\System32\\kernel32.dll"}) {
            auto x = pe::load(name);
            check(!x.sections.empty(), "Real DLL sections");
            check(!x.exports.empty(), "Real DLL exports");
            check(x.warnings.empty(), "Real DLL must parse without warnings");
            check(x.sha256.size() == 64, "Real DLL SHA256");
        }
        auto real64 = pe::load(L"C:\\Windows\\System32\\version.dll"),
             real32 = pe::load(L"C:\\Windows\\SysWOW64\\version.dll");
        check(real64.is64 && !real32.is64, "Real x64 and x86 DLLs");
        std::atomic_bool cancelled{true};
        bool cancelledRead = false;
        try {
            pe::parseBytes(fixture(true), {&cancelled});
        } catch (const pe::Cancelled&) {
            cancelledRead = true;
        }
        check(cancelledRead, "Parser cancellation must propagate");
        bool cancelledHash = false;
        try {
            pe::hash(abc, {&cancelled});
        } catch (const pe::Cancelled&) {
            cancelledHash = true;
        }
        check(cancelledHash, "Hash cancellation must propagate");
        auto reuseBytes = fixture(true);
        pe::Reader reusable(reuseBytes);
        check(reusable.parse().imports.size() == reusable.parse().imports.size(),
              "Reader can be reused without accumulated state");
        std::mt19937 rng(20261028);
        auto original = fixture(true);
        for (int i = 0; i < 1800; i++) {
            auto b = original;
            for (int n = 0; n < 1 + i % 5; n++)
                b[rng() % b.size()] = uint8_t(rng());
            try {
                auto x = pe::Reader(b).parse();
                check(x.imports.size() <= 250000, "Bounded imports");
            } catch (const pe::Error&) {
            }
        }
        check(pe::jsonEscape("a\"\\\n") == "\"a\\\"\\\\\\n\"", "JSON escaping");
        std::cout << "PASS: " << checks
                  << " assertions; PE32/PE32+, imports, delay loads, ordinals, forwarders, "
                     "malformed files, 1800 mutation cases and real Windows DLLs.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL after " << checks << " checks: " << e.what() << "\n";
        return 1;
    }
}
