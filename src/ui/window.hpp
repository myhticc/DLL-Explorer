#pragma once
#include "model.hpp"
#include <array>
#include <commctrl.h>
#include <exception>
#include <memory>
#include <mutex>
#include <thread>

namespace ui {
class InspectorWindow {
  public:
    explicit InspectorWindow(HINSTANCE instance);
    ~InspectorWindow();
    InspectorWindow(const InspectorWindow&) = delete;
    InspectorWindow& operator=(const InspectorWindow&) = delete;
    int run(const std::filesystem::path& initialFile = {});

  private:
    struct LoadResult {
        std::unique_ptr<pe::Image> image;
        std::exception_ptr failure;
    };
    enum Command : WORD {
        Open = 100,
        Reload,
        Save,
        CloseFile,
        Exit,
        Copy,
        CopyCell,
        CopyHash,
        SelectAll,
        Find,
        ClearFilter,
        About,
        FirstPage = 200
    };
    enum Control : int { ToolbarId = 300, PathId, TabsId, TableId, FilterId, ClearId, StatusId };
    static constexpr UINT loadCompleted = WM_APP + 1;
    static constexpr UINT_PTR filterTimer = 1, statusTimer = 2;
    static LRESULT CALLBACK windowProc(HWND window, UINT message, WPARAM wParam,
                                       LPARAM lParam) noexcept;
    LRESULT dispatch(UINT message, WPARAM wParam, LPARAM lParam);
    bool createControls();
    HMENU createMenus();
    void createAccelerators();
    void applyDpi(UINT dpi);
    void layout();
    void updateActions();
    void updateStatus(const std::wstring& text = {});
    void updateTabNames();
    void setPage(Page page);
    void refreshTable(bool rebuildColumns);
    void setFilter();
    void sortByColumn(size_t column);
    void updateSortIndicator();
    void command(WORD id);
    void openDialog();
    void saveDialog();
    void beginLoad(const std::filesystem::path& path);
    void finishLoad();
    void stopWorker() noexcept;
    void closeFile();
    void showContextMenu(LPARAM coordinates);
    std::vector<size_t> selectedRows() const;
    void copySelection();
    void copyToClipboard(const std::wstring& text);
    void error(const std::wstring& message, const wchar_t* title = L"DLL Explorer");
    LRESULT onNotify(NMHDR* notification);
    int px(int value) const noexcept {
        return MulDiv(value, int(dpi_), 96);
    }
    HINSTANCE instance_;
    HWND window_{}, toolbar_{}, path_{}, tabs_{}, table_{}, filter_{}, filterLabel_{}, clear_{},
        status_{}, pathLabel_{};
    HACCEL accelerators_{};
    HFONT font_{};
    HIMAGELIST rowHeight_{};
    UINT dpi_ = 96;
    Page page_ = Page::Overview;
    std::unique_ptr<pe::Image> image_;
    TableModel model_;
    std::array<std::vector<int>, pageCount> columnWidths_;
    std::optional<size_t> sortedColumn_;
    bool ascending_ = true, loading_ = false;
    int contextRow_ = -1, contextColumn_ = -1;
    std::filesystem::path requestedPath_;
    std::wstring currentFilter_, persistentStatus_;
    std::thread worker_;
    std::atomic_bool cancelled_{false};
    std::mutex resultMutex_;
    std::unique_ptr<LoadResult> result_;
};
} // namespace ui
