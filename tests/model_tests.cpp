#include "../src/ui/model.hpp"
#include <iostream>
#include <stdexcept>

namespace {
int checks = 0;
void check(bool condition, const char* message) {
    ++checks;
    if (!condition)
        throw std::runtime_error(message);
}
pe::Image example() {
    pe::Image image;
    image.path = L"C:\\test\\example.dll";
    image.machine = IMAGE_FILE_MACHINE_AMD64;
    image.is64 = true;
    image.imports = {{"KERNEL32.dll", "WriteFile", 12, false, false},
                     {"KERNEL32.dll", "CloseHandle", 2, false, false},
                     {"USER32.dll", "#9", 9, true, true}};
    image.dependencies = {{"KERNEL32.dll", 2, false},
                          {"USER32.dll", 1, true},
                          {"kernel32.DLL", 0, true},
                          {"Empty.dll", 0, false}};
    image.exports = {
        {"Ten", "", 10, 0x1200}, {"Two", "OTHER.Foo", 2, 0x1100}, {"Hundred", "", 100, 0x3000}};
    image.sections = {
        {".text", 0x1000, 10000, 0x400, 2048, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE},
        {".data", 0x4000, 2000, 0xC00, 512, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE}};
    image.warnings = {"Import directory: truncated."};
    return image;
}
} // namespace

int main() {
    try {
        const auto image = example();
        ui::TableModel model;
        for (int i = 0; i < ui::pageCount; ++i) {
            model.reset(&image, ui::Page(i));
            check(!model.columns().empty(), "Every page must have columns");
            for (const auto& row : model.allRows())
                check(row.cells.size() == model.columns().size(),
                      "Every row must match its schema");
        }
        model.reset(&image, ui::Page::Dependencies);
        check(model.size() == 3,
              "Case-insensitive dependency grouping retains zero-symbol modules");
        check(model.row(1).cells[0].text == L"KERNEL32.dll", "Library spelling preserved");
        check(model.row(1).cells[2].text == L"Standard, delay-load", "Combined load modes");
        model.reset(&image, ui::Page::Imports);
        model.filter(L"WRITEFILE");
        check(model.size() == 1 && model.row(0).cells[0].text == L"WriteFile",
              "Case-insensitive symbol filter");
        model.filter(L"kernel32.dll");
        check(model.size() == 2, "Filter by module");
        model.filter(L"no such symbol");
        check(model.size() == 0 && model.total() == 3, "Empty filter result preserves source rows");
        model.filter(L"");
        model.sort(2, true);
        check(model.row(0).cells[2].numeric == 2 && model.row(2).cells[2].numeric == 12,
              "Numeric import sorting");
        model.reset(&image, ui::Page::Exports);
        model.sort(1, true);
        check(model.row(0).cells[1].numeric == 2 && model.row(2).cells[1].numeric == 100,
              "Numeric ordinal sorting");
        model.sort(1, false);
        check(model.row(0).cells[1].numeric == 100, "Descending numeric sorting");
        model.filter(L"OTHER.Foo");
        check(model.size() == 1, "Forwarder filter");
        check(model.copyRows({0}) == L"Two\t2\t0x00001100\tOTHER.Foo", "Tab-separated copy");
        check(model.copyRows({100}).empty(), "Out-of-range selection ignored");
        model.reset(&image, ui::Page::Sections);
        model.sort(3, true);
        check(model.row(0).cells[0].text == L".data", "Raw size uses numeric sort keys");
        model.reset(&image, ui::Page::Overview);
        check(model.total() >= 20, "Complete overview");
        model.filter(L"SHA-256");
        check(model.size() == 1, "Overview properties are filterable");
        model.reset(nullptr, ui::Page::Exports);
        check(model.size() == 0, "Empty model");
        bool thrown = false;
        try {
            model.sort(50, true);
        } catch (const std::out_of_range&) {
            thrown = true;
        }
        check(thrown, "Invalid sort column rejected");
        check(ui::displayText("a\nb\tc") == L"a b c", "Control characters sanitized for tables");
        check(ui::formatBytes(1024) == L"1.0 KB", "Stable byte formatting");
        // Exercise the same indexed filter/sort path used by the virtual list view.
        auto large = example();
        large.exports.clear();
        for (uint32_t i = 0; i < 30000; ++i)
            large.exports.push_back({"Symbol" + std::to_string(i), "", i, i * 4});
        model.reset(&large, ui::Page::Exports);
        model.sort(1, false);
        model.filter(L"Symbol29");
        check(model.size() == 1111, "Large-table filtering");
        check(model.row(0).cells[1].numeric == 29999, "Filter preserves selected sort order");
        std::cout << "PASS: " << checks
                  << " view-model assertions; schemas, filtering, numeric sorting, copy, and 30000 "
                     "rows.\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << "FAIL: " << failure.what() << '\n';
        return 1;
    }
}
