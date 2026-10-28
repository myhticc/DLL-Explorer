#include "model.hpp"
#include <map>

namespace ui {
namespace {
std::wstring folded(std::wstring text) {
    if (!text.empty())
        CharLowerBuffW(text.data(), DWORD(text.size()));
    return text;
}
Cell textCell(std::wstring value) {
    return {std::move(value), std::nullopt};
}
Cell byteCell(uint64_t value) {
    return {formatBytes(value), value};
}
Cell numberCell(uint64_t value) {
    return {std::to_wstring(value), value};
}
Cell addressCell(uint64_t value, int width = 8) {
    return {pe::wide(pe::Image::hex(value, width)), value};
}
} // namespace

const wchar_t* pageName(Page page) noexcept {
    switch (page) {
    case Page::Overview:
        return L"Overview";
    case Page::Dependencies:
        return L"Dependencies";
    case Page::Imports:
        return L"Imports";
    case Page::Exports:
        return L"Exports";
    case Page::Sections:
        return L"Sections";
    case Page::Warnings:
        return L"Warnings";
    default:
        return L"";
    }
}

std::wstring displayText(const std::string& text) {
    auto result = pe::wide(text);
    for (auto& c : result)
        if (c < 32 || c == 127)
            c = L' ';
    return result;
}

std::wstring formatBytes(uint64_t size) {
    std::wostringstream result;
    result.imbue(std::locale::classic());
    if (size >= 1024 * 1024)
        result << std::fixed << std::setprecision(2) << double(size) / (1024 * 1024) << L" MB";
    else if (size >= 1024)
        result << std::fixed << std::setprecision(1) << double(size) / 1024 << L" KB";
    else
        result << size << L" B";
    return result.str();
}

void TableModel::add(std::vector<Cell> cells) {
    Row row{std::move(cells), {}};
    for (const auto& cell : row.cells) {
        row.searchable += folded(cell.text);
        row.searchable.push_back(L'\t');
    }
    rows_.push_back(std::move(row));
}

void TableModel::reset(const pe::Image* image, Page page) {
    rows_.clear();
    visible_.clear();
    query_.clear();
    sortColumn_.reset();
    ascending_ = true;
    switch (page) {
    case Page::Overview:
        columns_ = {{L"Property", 195}, {L"Value", 600}};
        break;
    case Page::Dependencies:
        columns_ = {{L"Library", 430}, {L"Imported symbols", 140}, {L"Load type", 180}};
        break;
    case Page::Imports:
        columns_ = {
            {L"Function", 350}, {L"Library", 270}, {L"Hint / ordinal", 120}, {L"Load type", 110}};
        break;
    case Page::Exports:
        columns_ = {{L"Function", 350}, {L"Ordinal", 90}, {L"RVA", 125}, {L"Forwarded to", 260}};
        break;
    case Page::Sections:
        columns_ = {{L"Section", 120},  {L"RVA", 120},          {L"Raw offset", 120},
                    {L"Raw size", 120}, {L"Virtual size", 120}, {L"Access", 90}};
        break;
    case Page::Warnings:
        columns_ = {{L"#", 55}, {L"Diagnostic", 800}};
        break;
    default:
        throw std::invalid_argument("Invalid inspector page.");
    }
    if (!image)
        return;
    const auto& file = *image;
    if (page == Page::Overview) {
        auto property = [&](const wchar_t* name, std::wstring value) {
            add({textCell(name), textCell(std::move(value))});
        };
        property(L"File name", file.path.filename().wstring());
        property(L"Full path", file.path.wstring());
        property(L"File type", (file.characteristics & IMAGE_FILE_DLL) ? L"Dynamic-link library"
                                                                       : L"Executable image");
        property(L"Architecture", displayText(file.architecture()) + L" (" +
                                      pe::wide(pe::Image::hex(file.machine, 4)) + L")");
        property(L"PE format", file.is64 ? L"PE32+ (64-bit)" : L"PE32 (32-bit)");
        property(L"Runtime", file.managed ? L"Managed (CLR directory declared)" : L"Native");
        property(L"File size",
                 formatBytes(file.fileSize) + L" (" + std::to_wstring(file.fileSize) + L" bytes)");
        property(L"Image size", formatBytes(file.imageSize) + L" (" +
                                    std::to_wstring(file.imageSize) + L" bytes)");
        property(L"Image base", pe::wide(pe::Image::hex(file.imageBase, file.is64 ? 16 : 8)));
        property(L"Entry point RVA", pe::wide(pe::Image::hex(file.entryPoint)));
        property(L"Subsystem", displayText(file.subsystemName()));
        property(L"Linker version",
                 std::to_wstring(file.linkerMajor) + L"." + std::to_wstring(file.linkerMinor));
        property(L"COFF timestamp (raw)", pe::wide(pe::Image::hex(file.timestamp)) + L" (" +
                                              std::to_wstring(file.timestamp) + L")");
        property(L"PE checksum", pe::wide(pe::Image::hex(file.checksum)));
        property(L"ASLR", (file.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
                              ? L"Declared"
                              : L"Not declared");
        property(L"DEP", (file.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
                             ? L"Declared"
                             : L"Not declared");
        property(L"Control Flow Guard",
                 (file.dllCharacteristics & 0x4000) ? L"Declared" : L"Not declared");
        property(L"Certificate table",
                 file.certificatePresent ? L"Present (signature not verified)" : L"Not present");
        property(L"Dependencies", std::to_wstring(file.libraryCount()));
        property(L"Imported symbols", std::to_wstring(file.imports.size()));
        property(L"Exported symbols", std::to_wstring(file.exports.size()));
        property(L"Sections", std::to_wstring(file.sections.size()));
        property(L"SHA-256", pe::wide(file.sha256));
    } else if (page == Page::Dependencies) {
        struct Library {
            std::wstring name;
            uint64_t count{};
            bool normal{}, delayed{};
        };
        std::map<std::wstring, Library> libraries;
        for (const auto& dependency : file.dependencies) {
            auto name = displayText(dependency.name);
            auto& library = libraries[folded(name)];
            if (library.name.empty())
                library.name = std::move(name);
            library.count += dependency.symbolCount;
            library.delayed |= dependency.delayed;
            library.normal |= !dependency.delayed;
        }
        for (const auto& pair : libraries) {
            const auto& lib = pair.second;
            add({textCell(lib.name), numberCell(lib.count),
                 textCell(lib.normal && lib.delayed ? L"Standard, delay-load"
                          : lib.delayed             ? L"Delay-load"
                                                    : L"Standard")});
        }
    } else if (page == Page::Imports) {
        rows_.reserve(file.imports.size());
        for (const auto& symbol : file.imports)
            add({textCell(displayText(symbol.name)),
                 textCell(displayText(symbol.library)),
                 {std::to_wstring(symbol.hint) + (symbol.ordinal ? L" (ordinal)" : L""),
                  symbol.hint},
                 textCell(symbol.delayed ? L"Delay-load" : L"Standard")});
    } else if (page == Page::Exports) {
        rows_.reserve(file.exports.size());
        for (const auto& symbol : file.exports)
            add({textCell(displayText(symbol.name)), numberCell(symbol.ordinal),
                 addressCell(symbol.rva), textCell(displayText(symbol.forwarder))});
    } else if (page == Page::Sections) {
        for (const auto& section : file.sections) {
            std::wstring flags;
            if (section.flags & IMAGE_SCN_MEM_READ)
                flags += L"R";
            if (section.flags & IMAGE_SCN_MEM_WRITE)
                flags += L"W";
            if (section.flags & IMAGE_SCN_MEM_EXECUTE)
                flags += L"X";
            add({textCell(displayText(section.name)), addressCell(section.rva),
                 addressCell(section.rawOffset), byteCell(section.rawSize),
                 byteCell(section.virtualSize), textCell(flags)});
        }
    } else if (page == Page::Warnings) {
        for (size_t i = 0; i < file.warnings.size(); ++i)
            add({numberCell(i + 1), textCell(displayText(file.warnings[i]))});
    }
    refresh();
}

void TableModel::filter(const std::wstring& text) {
    query_ = folded(text);
    refresh();
}

void TableModel::sort(size_t column, bool ascending) {
    if (column >= columns_.size())
        throw std::out_of_range("Invalid table sort column.");
    sortColumn_ = column;
    ascending_ = ascending;
    refresh();
}

void TableModel::refresh() {
    visible_.clear();
    visible_.reserve(rows_.size());
    for (size_t i = 0; i < rows_.size(); ++i)
        if (query_.empty() || rows_[i].searchable.find(query_) != std::wstring::npos)
            visible_.push_back(i);
    if (!sortColumn_)
        return;
    const size_t column = *sortColumn_;
    std::stable_sort(visible_.begin(), visible_.end(), [&](size_t left, size_t right) {
        const auto& a = rows_[left].cells[column];
        const auto& b = rows_[right].cells[column];
        int comparison = 0;
        if (a.numeric && b.numeric)
            comparison = *a.numeric < *b.numeric ? -1 : *a.numeric > *b.numeric ? 1 : 0;
        else
            comparison = CompareStringOrdinal(a.text.c_str(), int(a.text.size()), b.text.c_str(),
                                              int(b.text.size()), TRUE) -
                         CSTR_EQUAL;
        return ascending_ ? comparison < 0 : comparison > 0;
    });
}

std::wstring TableModel::copyRows(const std::vector<size_t>& selected) const {
    std::wstring result;
    for (size_t index : selected) {
        if (index >= size())
            continue;
        if (!result.empty())
            result += L"\r\n";
        const auto& values = row(index).cells;
        for (size_t column = 0; column < values.size(); ++column) {
            if (column)
                result.push_back(L'\t');
            result += values[column].text;
        }
    }
    return result;
}
} // namespace ui
