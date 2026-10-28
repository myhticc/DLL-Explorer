#include "../pe.hpp"
namespace pe {
namespace {
std::wstring textField(const std::string& value) {
    std::wstring result;
    for (wchar_t character : wide(value)) {
        if (character == L'\\')
            result += L"\\\\";
        else if (character == L'\r')
            result += L"\\r";
        else if (character == L'\n')
            result += L"\\n";
        else if (character == L'\t')
            result += L"\\t";
        else if (character < 32 || character == 127)
            result += L"\\x" + wide(Image::hex(uint16_t(character), 2).substr(2));
        else
            result.push_back(character);
    }
    return result;
}
} // namespace
std::string jsonEscape(const std::string& s) {
    return jsonUtf8(utf8(wide(s)));
}
std::string jsonUtf8(const std::string& s) {
    std::ostringstream o;
    o << '"';
    for (unsigned char c : s) {
        switch (c) {
        case '"':
            o << "\\\"";
            break;
        case '\\':
            o << "\\\\";
            break;
        case '\n':
            o << "\\n";
            break;
        case '\r':
            o << "\\r";
            break;
        case '\t':
            o << "\\t";
            break;
        default:
            if (c < 32)
                o << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << int(c) << std::dec;
            else
                o << c;
        }
    }
    o << '"';
    return o.str();
}
std::string json(const Image& x) {
    auto q = [](const std::string& s) { return jsonEscape(s); };
    std::ostringstream o;
    o.imbue(std::locale::classic());
    o << "{\n  \"schema_version\": 1,\n  \"application\": "
      << q(std::string("DLL Explorer ") + Version)
      << ",\n  \"path\": " << jsonUtf8(utf8(x.path.wstring()))
      << ",\n  \"architecture\": " << q(x.architecture())
      << ",\n  \"format\": " << q(x.is64 ? "PE32+" : "PE32")
      << ",\n  \"is_dll\": " << ((x.characteristics & IMAGE_FILE_DLL) ? "true" : "false")
      << ",\n  \"managed\": " << (x.managed ? "true" : "false")
      << ",\n  \"file_size\": " << x.fileSize
      << ",\n  \"image_base\": " << q(Image::hex(x.imageBase, x.is64 ? 16 : 8))
      << ",\n  \"entry_point_rva\": " << q(Image::hex(x.entryPoint))
      << ",\n  \"image_size\": " << x.imageSize << ",\n  \"coff_timestamp\": " << x.timestamp
      << ",\n  \"subsystem\": " << q(x.subsystemName()) << ",\n  \"sha256\": " << q(x.sha256)
      << ",\n  \"certificate_table_present\": " << (x.certificatePresent ? "true" : "false")
      << ",\n  \"aslr\": "
      << ((x.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) ? "true" : "false")
      << ",\n  \"dep\": "
      << ((x.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) ? "true" : "false")
      << ",\n  \"cfg\": " << ((x.dllCharacteristics & 0x4000) ? "true" : "false")
      << ",\n  \"library_count\": " << x.libraryCount() << ",\n  \"dependencies\": [";
    bool first = true;
    for (const auto& dependency : x.dependencies) {
        if (!first)
            o << ',';
        first = false;
        o << "\n    {\"library\": " << q(dependency.name)
          << ", \"symbol_count\": " << dependency.symbolCount
          << ", \"delay_load\": " << (dependency.delayed ? "true" : "false") << '}';
    }
    o << "\n  ],\n  \"imports\": [";
    first = true;
    for (const auto& v : x.imports) {
        if (!first)
            o << ',';
        first = false;
        o << "\n    {\"library\": " << q(v.library) << ", \"name\": " << q(v.name)
          << ", \"hint_or_ordinal\": " << v.hint
          << ", \"by_ordinal\": " << (v.ordinal ? "true" : "false")
          << ", \"delay_load\": " << (v.delayed ? "true" : "false") << '}';
    }
    o << "\n  ],\n  \"exports\": [";
    first = true;
    for (const auto& v : x.exports) {
        if (!first)
            o << ',';
        first = false;
        o << "\n    {\"name\": " << q(v.name) << ", \"ordinal\": " << v.ordinal
          << ", \"rva\": " << q(Image::hex(v.rva)) << ", \"forwarder\": " << q(v.forwarder) << '}';
    }
    o << "\n  ],\n  \"sections\": [";
    first = true;
    for (const auto& v : x.sections) {
        if (!first)
            o << ',';
        first = false;
        o << "\n    {\"name\": " << q(v.name) << ", \"rva\": " << q(Image::hex(v.rva))
          << ", \"raw_offset\": " << q(Image::hex(v.rawOffset)) << ", \"raw_size\": " << v.rawSize
          << ", \"virtual_size\": " << v.virtualSize
          << ", \"characteristics\": " << q(Image::hex(v.flags)) << '}';
    }
    o << "\n  ],\n  \"warnings\": [";
    first = true;
    for (const auto& v : x.warnings) {
        if (!first)
            o << ", ";
        first = false;
        o << q(v);
    }
    o << "]\n}\n";
    return o.str();
}
std::wstring report(const Image& x) {
    std::wostringstream o;
    o.imbue(std::locale::classic());
    o << L"DLL Explorer " << wide(Version) << L"\r\n" << x.path.wstring() << L"\r\n\r\n";
    o << L"Architecture: " << wide(x.architecture()) << L" (" << (x.is64 ? L"PE32+" : L"PE32")
      << L")\r\nFile size: " << x.fileSize << L" bytes\r\nImage base: "
      << wide(Image::hex(x.imageBase, x.is64 ? 16 : 8)) << L"\r\nEntry point RVA: "
      << wide(Image::hex(x.entryPoint)) << L"\r\nSubsystem: " << wide(x.subsystemName())
      << L"\r\nSHA-256: " << wide(x.sha256) << L"\r\n\r\n";
    o << L"DEPENDENCIES (" << x.libraryCount() << L")\r\n";
    for (const auto& dependency : x.dependencies)
        o << textField(dependency.name) << L"\t" << dependency.symbolCount << L" symbols"
          << (dependency.delayed ? L"\t[delay-load]" : L"") << L"\r\n";
    o << L"\r\n";
    o << L"IMPORTS (" << x.imports.size() << L" symbols, " << x.libraryCount()
      << L" libraries)\r\n";
    for (const auto& v : x.imports)
        o << textField(v.library) << L"\t" << textField(v.name)
          << (v.delayed ? L"\t[delay-load]" : L"") << L"\r\n";
    o << L"\r\nEXPORTS (" << x.exports.size() << L")\r\n";
    for (const auto& v : x.exports)
        o << v.ordinal << L"\t" << textField(v.name) << L"\t" << wide(Image::hex(v.rva))
          << (v.forwarder.empty() ? L"" : L"\t" + textField(v.forwarder)) << L"\r\n";
    o << L"\r\nSECTIONS\r\n";
    for (const auto& s : x.sections)
        o << textField(s.name) << L"\t" << wide(Image::hex(s.rva)) << L"\t" << s.rawSize
          << L" bytes\r\n";
    if (!x.warnings.empty()) {
        o << L"\r\nWARNINGS\r\n";
        for (const auto& w : x.warnings)
            o << textField(w) << L"\r\n";
    }
    return o.str();
}
} // namespace pe
