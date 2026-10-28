#pragma once
#include "../pe.hpp"
#include <optional>

namespace ui {
enum class Page { Overview, Dependencies, Imports, Exports, Sections, Warnings, Count };
constexpr int pageCount = int(Page::Count);
const wchar_t* pageName(Page page) noexcept;
std::wstring displayText(const std::string& text);
std::wstring formatBytes(uint64_t size);

struct Column {
    std::wstring title;
    int width;
};
struct Cell {
    std::wstring text;
    std::optional<uint64_t> numeric;
};
struct Row {
    std::vector<Cell> cells;
    std::wstring searchable;
};

// UI-independent view model. Filtering and sorting operate on row indices,
// so typing never rebuilds the symbol strings or changes the source image.
class TableModel {
  public:
    void reset(const pe::Image* image, Page page);
    void filter(const std::wstring& text);
    void sort(size_t column, bool ascending);
    const std::vector<Column>& columns() const noexcept {
        return columns_;
    }
    const std::vector<Row>& allRows() const noexcept {
        return rows_;
    }
    const Row& row(size_t visibleIndex) const {
        return rows_.at(visible_.at(visibleIndex));
    }
    size_t sourceIndex(size_t visibleIndex) const {
        return visible_.at(visibleIndex);
    }
    size_t size() const noexcept {
        return visible_.size();
    }
    size_t total() const noexcept {
        return rows_.size();
    }
    std::wstring copyRows(const std::vector<size_t>& selected) const;

  private:
    void add(std::vector<Cell> cells);
    void refresh();
    std::vector<Column> columns_;
    std::vector<Row> rows_;
    std::vector<size_t> visible_;
    std::wstring query_;
    std::optional<size_t> sortColumn_;
    bool ascending_ = true;
};
} // namespace ui
