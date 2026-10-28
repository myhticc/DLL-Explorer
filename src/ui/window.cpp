#include "window.hpp"
#include <commdlg.h>
#include <cstring>
#include <shellapi.h>
#include <uxtheme.h>
#include <windowsx.h>

namespace ui {
namespace {
constexpr wchar_t className[] = L"DLLExplorer.Inspector.1";
std::wstring controlText(HWND control) {
    const int length = GetWindowTextLengthW(control);
    std::wstring text(size_t(length) + 1, L'\0');
    const int copied = GetWindowTextW(control, text.data(), length + 1);
    text.resize(size_t(copied));
    return text;
}
void enableMenu(HMENU menu, UINT id, bool enabled) {
    EnableMenuItem(menu, id, MF_BYCOMMAND | (enabled ? MF_ENABLED : MF_GRAYED));
}
} // namespace

InspectorWindow::InspectorWindow(HINSTANCE instance) : instance_(instance) {}
InspectorWindow::~InspectorWindow() {
    stopWorker();
    if (window_ && IsWindow(window_))
        DestroyWindow(window_);
    if (accelerators_)
        DestroyAcceleratorTable(accelerators_);
    if (rowHeight_)
        ImageList_Destroy(rowHeight_);
    if (font_)
        DeleteObject(font_);
}

HMENU InspectorWindow::createMenus() {
    const HMENU menu = CreateMenu();
    const HMENU file = CreatePopupMenu();
    AppendMenuW(file, MF_STRING, Open, L"&Open...\tCtrl+O");
    AppendMenuW(file, MF_STRING, Reload, L"&Reload\tF5");
    AppendMenuW(file, MF_STRING, Save, L"&Save report...\tCtrl+S");
    AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(file, MF_STRING, CloseFile, L"&Close file\tCtrl+W");
    AppendMenuW(file, MF_STRING, Exit, L"E&xit\tAlt+F4");
    AppendMenuW(menu, MF_POPUP, UINT_PTR(file), L"&File");
    const HMENU edit = CreatePopupMenu();
    AppendMenuW(edit, MF_STRING, Copy, L"&Copy selected rows\tCtrl+C");
    AppendMenuW(edit, MF_STRING, CopyHash, L"Copy &SHA-256");
    AppendMenuW(edit, MF_STRING, SelectAll, L"Select &all\tCtrl+A");
    AppendMenuW(edit, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(edit, MF_STRING, Find, L"&Filter\tCtrl+F");
    AppendMenuW(edit, MF_STRING, ClearFilter, L"Clear filter\tEsc");
    AppendMenuW(menu, MF_POPUP, UINT_PTR(edit), L"&Edit");
    const HMENU view = CreatePopupMenu();
    for (int i = 0; i < pageCount; ++i) {
        const auto label = std::wstring(pageName(Page(i))) + L"\tCtrl+" + std::to_wstring(i + 1);
        AppendMenuW(view, MF_STRING, FirstPage + UINT(i), label.c_str());
    }
    AppendMenuW(menu, MF_POPUP, UINT_PTR(view), L"&View");
    const HMENU help = CreatePopupMenu();
    AppendMenuW(help, MF_STRING, About, L"&About DLL Explorer");
    AppendMenuW(menu, MF_POPUP, UINT_PTR(help), L"&Help");
    return menu;
}

void InspectorWindow::createAccelerators() {
    std::vector<ACCEL> entries{{FVIRTKEY | FCONTROL, 'O', Open},
                               {FVIRTKEY | FCONTROL, 'S', Save},
                               {FVIRTKEY | FCONTROL, 'W', CloseFile},
                               {FVIRTKEY | FCONTROL, 'F', Find},
                               {FVIRTKEY, VK_F5, Reload}};
    for (int i = 0; i < pageCount; ++i)
        entries.push_back({FVIRTKEY | FCONTROL, WORD('1' + i), WORD(FirstPage + i)});
    accelerators_ = CreateAcceleratorTableW(entries.data(), int(entries.size()));
    if (!accelerators_)
        throw pe::Error("Could not create keyboard shortcuts.");
}

bool InspectorWindow::createControls() {
    toolbar_ =
        CreateWindowExW(0, TOOLBARCLASSNAMEW, nullptr,
                        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TBSTYLE_FLAT | TBSTYLE_LIST |
                            TBSTYLE_TOOLTIPS | CCS_NODIVIDER | CCS_NORESIZE | CCS_NOPARENTALIGN,
                        0, 0, 0, 0, window_, HMENU(ToolbarId), instance_, nullptr);
    SendMessageW(toolbar_, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
    SendMessageW(toolbar_, TB_SETMAXTEXTROWS, 1, 0);
    auto tool = [&](Command id, const wchar_t* label) {
        TBBUTTON button{};
        button.iBitmap = I_IMAGENONE;
        button.idCommand = id;
        button.fsState = TBSTATE_ENABLED;
        button.fsStyle = BTNS_BUTTON | BTNS_AUTOSIZE | BTNS_SHOWTEXT;
        button.iString = INT_PTR(label);
        SendMessageW(toolbar_, TB_ADDBUTTONSW, 1, LPARAM(&button));
    };
    tool(Open, L"Open...");
    tool(Reload, L"Reload");
    TBBUTTON separator{};
    separator.fsStyle = BTNS_SEP;
    SendMessageW(toolbar_, TB_ADDBUTTONSW, 1, LPARAM(&separator));
    tool(Save, L"Save report...");
    tool(Copy, L"Copy");
    filterLabel_ = CreateWindowExW(0, L"STATIC", L"Filter:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                                   0, 0, 0, 0, window_, nullptr, instance_, nullptr);
    filter_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr,
                              WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0,
                              window_, HMENU(FilterId), instance_, nullptr);
    SendMessageW(filter_, EM_SETCUEBANNER, FALSE, LPARAM(L"Filter current view (Ctrl+F)"));
    SendMessageW(filter_, EM_SETLIMITTEXT, 512, 0);
    clear_ =
        CreateWindowExW(0, L"BUTTON", L"Clear", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                        0, 0, 0, 0, window_, HMENU(ClearId), instance_, nullptr);
    pathLabel_ = CreateWindowExW(0, L"STATIC", L"File:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, 0,
                                 0, 0, 0, window_, nullptr, instance_, nullptr);
    path_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr,
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_READONLY | ES_AUTOHSCROLL, 0, 0,
                            0, 0, window_, HMENU(PathId), instance_, nullptr);
    tabs_ = CreateWindowExW(0, WC_TABCONTROLW, nullptr,
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS, 0, 0, 0, 0,
                            window_, HMENU(TabsId), instance_, nullptr);
    for (int i = 0; i < pageCount; ++i) {
        TCITEMW item{};
        item.mask = TCIF_TEXT;
        item.pszText = const_cast<wchar_t*>(pageName(Page(i)));
        TabCtrl_InsertItem(tabs_, i, &item);
    }
    table_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"Binary details",
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_OWNERDATA |
                                 LVS_SHOWSELALWAYS,
                             0, 0, 0, 0, window_, HMENU(TableId), instance_, nullptr);
    ListView_SetExtendedListViewStyle(table_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER |
                                                  LVS_EX_LABELTIP | LVS_EX_GRIDLINES);
    SetWindowTheme(table_, L"Explorer", nullptr);
    ListView_SetBkColor(table_, GetSysColor(COLOR_WINDOW));
    ListView_SetTextBkColor(table_, GetSysColor(COLOR_WINDOW));
    ListView_SetTextColor(table_, GetSysColor(COLOR_WINDOWTEXT));
    status_ = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr, WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                              0, 0, 0, 0, window_, HMENU(StatusId), instance_, nullptr);
    for (HWND control :
         {toolbar_, filterLabel_, filter_, clear_, pathLabel_, path_, tabs_, table_, status_})
        if (!control)
            return false;
    DragAcceptFiles(window_, TRUE);
    applyDpi(GetDpiForWindow(window_));
    model_.reset(nullptr, page_);
    refreshTable(true);
    updateActions();
    return true;
}

void InspectorWindow::applyDpi(UINT dpi) {
    dpi_ = dpi ? dpi : 96;
    HFONT previous = font_;
    font_ = CreateFontW(-MulDiv(9, int(dpi_), 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                        DEFAULT_PITCH, L"Segoe UI");
    if (!font_) {
        font_ = previous;
        throw pe::Error("Could not create the interface font.");
    }
    for (HWND control :
         {toolbar_, filterLabel_, filter_, clear_, pathLabel_, path_, tabs_, table_, status_})
        if (control)
            SendMessageW(control, WM_SETFONT, WPARAM(font_), TRUE);
    if (previous)
        DeleteObject(previous);
    const HIMAGELIST newHeight = ImageList_Create(1, px(21), ILC_COLOR32, 1, 1);
    if (!newHeight)
        throw pe::Error("Could not initialize table rows.");
    ListView_SetImageList(table_, newHeight, LVSIL_SMALL);
    if (rowHeight_)
        ImageList_Destroy(rowHeight_);
    rowHeight_ = newHeight;
    SendMessageW(toolbar_, TB_SETBUTTONSIZE, 0, MAKELPARAM(px(72), px(27)));
    layout();
}

void InspectorWindow::layout() {
    if (!table_)
        return;
    RECT client{};
    GetClientRect(window_, &client);
    const int width = client.right;
    SendMessageW(status_, WM_SIZE, 0, 0);
    RECT statusRect{};
    GetWindowRect(status_, &statusRect);
    const int bottom = client.bottom - (statusRect.bottom - statusRect.top);
    const int statusParts[] = {std::max(px(210), width - px(420)), width - px(190), -1};
    SendMessageW(status_, SB_SETPARTS, 3, LPARAM(statusParts));
    MoveWindow(toolbar_, px(8), px(4), width - px(360), px(30), TRUE);
    MoveWindow(filterLabel_, width - px(336), px(5), px(36), px(26), TRUE);
    MoveWindow(filter_, width - px(297), px(6), px(222), px(24), TRUE);
    MoveWindow(clear_, width - px(68), px(5), px(56), px(26), TRUE);
    MoveWindow(pathLabel_, px(12), px(41), px(32), px(24), TRUE);
    MoveWindow(path_, px(48), px(41), width - px(60), px(24), TRUE);
    const int tabX = px(12), tabY = px(78);
    const int tabWidth = width - px(24), tabHeight = std::max(px(70), bottom - tabY - px(10));
    MoveWindow(tabs_, tabX, tabY, tabWidth, tabHeight, TRUE);
    RECT content{0, 0, tabWidth, tabHeight};
    TabCtrl_AdjustRect(tabs_, FALSE, &content);
    MoveWindow(table_, tabX + content.left + px(5), tabY + content.top + px(5),
               std::max(px(50), int(content.right - content.left) - px(10)),
               std::max(px(40), int(content.bottom - content.top) - px(10)), TRUE);
    if (page_ == Page::Overview || page_ == Page::Warnings) {
        RECT tableRect{};
        GetClientRect(table_, &tableRect);
        if (model_.columns().size() >= 2)
            ListView_SetColumnWidth(
                table_, 1,
                std::max(px(300),
                         int(tableRect.right) - ListView_GetColumnWidth(table_, 0) - px(22)));
    }
}

void InspectorWindow::updateStatus(const std::wstring& text) {
    if (!status_)
        return;
    std::wstring message = text.empty() ? persistentStatus_ : text;
    if (message.empty())
        message = image_ ? L"Ready" : L"Open a DLL or EXE to begin.";
    SendMessageW(status_, SB_SETTEXTW, 0, LPARAM(message.c_str()));
    const auto format = image_ ? pe::wide(image_->architecture()) + L"  |  " +
                                     std::to_wstring(image_->libraryCount()) + L" dependencies"
                               : std::wstring{};
    SendMessageW(status_, SB_SETTEXTW, 1, LPARAM(format.c_str()));
    const auto count =
        std::to_wstring(model_.size()) + L" / " + std::to_wstring(model_.total()) + L" rows";
    SendMessageW(status_, SB_SETTEXTW, 2, LPARAM(count.c_str()));
}

void InspectorWindow::updateActions() {
    const bool hasImage = image_ != nullptr;
    const bool hasSelection = table_ && ListView_GetSelectedCount(table_) != 0;
    const auto menu = GetMenu(window_);
    for (auto id : {Reload, Save, CloseFile, CopyHash})
        enableMenu(menu, id, hasImage && !loading_);
    enableMenu(menu, Copy, hasSelection);
    enableMenu(menu, SelectAll, model_.size() != 0);
    enableMenu(menu, Find, hasImage);
    enableMenu(menu, ClearFilter, !currentFilter_.empty());
    for (auto id : {Reload, Save})
        SendMessageW(toolbar_, TB_ENABLEBUTTON, id, MAKELONG(hasImage && !loading_, 0));
    SendMessageW(toolbar_, TB_ENABLEBUTTON, Copy, MAKELONG(hasSelection, 0));
    EnableWindow(filter_, hasImage);
    EnableWindow(clear_, !currentFilter_.empty());
    for (int i = 0; i < pageCount; ++i)
        CheckMenuItem(menu, FirstPage + UINT(i),
                      MF_BYCOMMAND | (page_ == Page(i) ? MF_CHECKED : MF_UNCHECKED));
}

void InspectorWindow::updateTabNames() {
    const size_t counts[] = {0,
                             image_ ? image_->libraryCount() : 0,
                             image_ ? image_->imports.size() : 0,
                             image_ ? image_->exports.size() : 0,
                             image_ ? image_->sections.size() : 0,
                             image_ ? image_->warnings.size() : 0};
    for (int i = 0; i < pageCount; ++i) {
        auto name = std::wstring(pageName(Page(i)));
        if (image_ && i != 0)
            name += L" (" + std::to_wstring(counts[i]) + L")";
        TCITEMW item{};
        item.mask = TCIF_TEXT;
        item.pszText = name.data();
        TabCtrl_SetItem(tabs_, i, &item);
    }
}

void InspectorWindow::refreshTable(bool rebuildColumns) {
    SendMessageW(table_, WM_SETREDRAW, FALSE, 0);
    ListView_SetItemCountEx(table_, 0, LVSICF_NOINVALIDATEALL);
    if (rebuildColumns) {
        while (ListView_DeleteColumn(table_, 0)) {
        }
        const auto& columns = model_.columns();
        const auto& widths = columnWidths_[size_t(page_)];
        for (size_t i = 0; i < columns.size(); ++i) {
            LVCOLUMNW column{};
            column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
            column.pszText = const_cast<wchar_t*>(columns[i].title.c_str());
            column.cx = px(i < widths.size() ? widths[i] : columns[i].width);
            column.fmt = LVCFMT_LEFT;
            ListView_InsertColumn(table_, int(i), &column);
        }
    }
    ListView_SetItemCountEx(table_, int(model_.size()), LVSICF_NOSCROLL);
    SendMessageW(table_, WM_SETREDRAW, TRUE, 0);
    updateSortIndicator();
    layout();
    InvalidateRect(table_, nullptr, TRUE);
    updateStatus();
    updateActions();
}

void InspectorWindow::setPage(Page page) {
    if (page < Page::Overview || page >= Page::Count)
        return;
    auto& widths = columnWidths_[size_t(page_)];
    widths.clear();
    for (size_t i = 0; i < model_.columns().size(); ++i)
        widths.push_back(MulDiv(ListView_GetColumnWidth(table_, int(i)), 96, int(dpi_)));
    page_ = page;
    TabCtrl_SetCurSel(tabs_, int(page_));
    model_.reset(image_.get(), page_);
    model_.filter(currentFilter_);
    sortedColumn_.reset();
    ascending_ = true;
    refreshTable(true);
}

void InspectorWindow::setFilter() {
    KillTimer(window_, filterTimer);
    currentFilter_ = controlText(filter_);
    model_.filter(currentFilter_);
    refreshTable(false);
}

void InspectorWindow::sortByColumn(size_t column) {
    if (column >= model_.columns().size())
        return;
    ascending_ = sortedColumn_ && *sortedColumn_ == column ? !ascending_ : true;
    sortedColumn_ = column;
    model_.sort(column, ascending_);
    refreshTable(false);
}

void InspectorWindow::updateSortIndicator() {
    const HWND header = ListView_GetHeader(table_);
    for (size_t i = 0; i < model_.columns().size(); ++i) {
        HDITEMW item{};
        item.mask = HDI_FORMAT;
        Header_GetItem(header, int(i), &item);
        item.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (sortedColumn_ && *sortedColumn_ == i)
            item.fmt |= ascending_ ? HDF_SORTUP : HDF_SORTDOWN;
        Header_SetItem(header, int(i), &item);
    }
}

void InspectorWindow::openDialog() {
    std::vector<wchar_t> path(32768);
    OPENFILENAMEW options{sizeof(options)};
    options.hwndOwner = window_;
    options.lpstrTitle = L"Open binary";
    options.lpstrFilter =
        L"Windows binaries (*.dll;*.exe;*.sys;*.ocx;*.cpl)\0*.dll;*.exe;*.sys;*.ocx;*.cpl\0All "
        L"files (*.*)\0*.*\0\0";
    options.lpstrFile = path.data();
    options.nMaxFile = DWORD(path.size());
    options.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&options))
        beginLoad(path.data());
    else if (CommDlgExtendedError())
        error(L"The file dialog could not be opened.");
}

void InspectorWindow::saveDialog() {
    if (!image_ || loading_)
        return;
    std::vector<wchar_t> path(32768);
    const auto name = image_->path.stem().wstring() + L"-report.json";
    wcsncpy_s(path.data(), path.size(), name.c_str(), _TRUNCATE);
    OPENFILENAMEW options{sizeof(options)};
    options.hwndOwner = window_;
    options.lpstrTitle = L"Save inspection report";
    options.lpstrFilter = L"JSON report (*.json)\0*.json\0Text report (*.txt)\0*.txt\0\0";
    options.lpstrFile = path.data();
    options.nMaxFile = DWORD(path.size());
    options.lpstrDefExt = L"json";
    options.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&options)) {
        if (CommDlgExtendedError())
            error(L"The save dialog could not be opened.");
        return;
    }
    try {
        const auto target = std::filesystem::path(path.data());
        const bool text = _wcsicmp(target.extension().c_str(), L".txt") == 0;
        pe::writeReport(target, text ? pe::utf8(pe::report(*image_)) : pe::json(*image_),
                        image_->path);
        updateStatus(L"Report saved.");
        SetTimer(window_, statusTimer, 3500, nullptr);
    } catch (const std::exception& failure) {
        error(pe::wide(failure.what()), L"Could not save report");
    }
}

void InspectorWindow::stopWorker() noexcept {
    cancelled_.store(true, std::memory_order_relaxed);
    if (worker_.joinable())
        worker_.join();
    std::lock_guard<std::mutex> lock(resultMutex_);
    result_.reset();
}

void InspectorWindow::beginLoad(const std::filesystem::path& path) {
    // No detached thread may outlive this controller or post an owned pointer to a window.
    const auto absolute = std::filesystem::absolute(path);
    stopWorker();
    requestedPath_ = absolute;
    cancelled_.store(false, std::memory_order_relaxed);
    loading_ = true;
    persistentStatus_ = L"Reading " + requestedPath_.filename().wstring() + L"...";
    updateStatus();
    updateActions();
    try {
        const auto input = requestedPath_;
        worker_ = std::thread([this, input, result = std::make_unique<LoadResult>()]() mutable {
            try {
                result->image = std::make_unique<pe::Image>(pe::load(input, {&cancelled_}));
            } catch (const pe::Cancelled&) {
                return;
            } catch (...) {
                result->failure = std::current_exception();
            }
            if (cancelled_.load(std::memory_order_relaxed))
                return;
            {
                std::lock_guard<std::mutex> lock(resultMutex_);
                result_ = std::move(result);
            }
            PostMessageW(window_, loadCompleted, 0, 0);
        });
    } catch (...) {
        loading_ = false;
        persistentStatus_ = L"Could not start inspection.";
        updateStatus();
        updateActions();
        throw;
    }
}

void InspectorWindow::finishLoad() {
    std::unique_ptr<LoadResult> result;
    {
        std::lock_guard<std::mutex> lock(resultMutex_);
        result = std::move(result_);
    }
    // Ignore queued messages belonging to a cancelled inspection.
    if (!result)
        return;
    if (worker_.joinable())
        worker_.join();
    loading_ = false;
    if (result->image) {
        image_ = std::move(result->image);
        SetWindowTextW(path_, image_->path.c_str());
        SetWindowTextW(window_, (image_->path.filename().wstring() + L" - DLL Explorer").c_str());
        persistentStatus_ = image_->warnings.empty()
                                ? L"Ready"
                                : std::to_wstring(image_->warnings.size()) +
                                      L" parser warning(s). See the Warnings tab.";
        currentFilter_.clear();
        SetWindowTextW(filter_, L"");
        updateTabNames();
        setPage(Page::Overview);
    } else {
        persistentStatus_ = L"Could not open " + requestedPath_.filename().wstring() + L".";
        updateStatus();
        updateActions();
        try {
            if (result->failure)
                std::rethrow_exception(result->failure);
            throw pe::Error("Inspection failed.");
        } catch (const std::exception& failure) {
            error(pe::wide(failure.what()), L"Could not open binary");
        }
    }
}

void InspectorWindow::closeFile() {
    stopWorker();
    loading_ = false;
    image_.reset();
    currentFilter_.clear();
    persistentStatus_.clear();
    SetWindowTextW(filter_, L"");
    SetWindowTextW(path_, L"");
    SetWindowTextW(window_, L"DLL Explorer");
    updateTabNames();
    setPage(Page::Overview);
}

std::vector<size_t> InspectorWindow::selectedRows() const {
    std::vector<size_t> selected;
    selected.reserve(size_t(ListView_GetSelectedCount(table_)));
    int index = -1;
    while ((index = ListView_GetNextItem(table_, index, LVNI_SELECTED)) >= 0)
        selected.push_back(size_t(index));
    return selected;
}

void InspectorWindow::copyToClipboard(const std::wstring& text) {
    if (text.empty())
        return;
    if (!OpenClipboard(window_)) {
        updateStatus(L"The clipboard is busy. Try again.");
        return;
    }
    struct CloseClipboardOnExit {
        ~CloseClipboardOnExit() {
            CloseClipboard();
        }
    } close;
    const size_t length = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, length);
    if (!memory)
        throw std::bad_alloc();
    void* buffer = GlobalLock(memory);
    if (!buffer) {
        GlobalFree(memory);
        throw pe::Error("Could not prepare clipboard data.");
    }
    memcpy(buffer, text.c_str(), length);
    GlobalUnlock(memory);
    if (!EmptyClipboard() || !SetClipboardData(CF_UNICODETEXT, memory)) {
        GlobalFree(memory);
        throw pe::Error("Could not copy to the clipboard.");
    }
    updateStatus(L"Copied to clipboard.");
    SetTimer(window_, statusTimer, 3500, nullptr);
}
void InspectorWindow::copySelection() {
    copyToClipboard(model_.copyRows(selectedRows()));
}

void InspectorWindow::showContextMenu(LPARAM coordinates) {
    POINT point{GET_X_LPARAM(coordinates), GET_Y_LPARAM(coordinates)};
    contextRow_ = -1;
    contextColumn_ = -1;
    if (point.x == -1 && point.y == -1) {
        contextRow_ = ListView_GetNextItem(table_, -1, LVNI_SELECTED);
        RECT rect{};
        if (contextRow_ >= 0)
            ListView_GetItemRect(table_, contextRow_, &rect, LVIR_BOUNDS);
        point = {rect.left + px(12), rect.bottom + px(3)};
        ClientToScreen(table_, &point);
    } else {
        POINT local = point;
        ScreenToClient(table_, &local);
        LVHITTESTINFO hit{};
        hit.pt = local;
        contextRow_ = ListView_SubItemHitTest(table_, &hit);
        contextColumn_ = hit.iSubItem;
        if (contextRow_ >= 0 &&
            !(ListView_GetItemState(table_, contextRow_, LVIS_SELECTED) & LVIS_SELECTED)) {
            ListView_SetItemState(table_, -1, 0, LVIS_SELECTED);
            ListView_SetItemState(table_, contextRow_, LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
        }
    }
    HMENU popup = CreatePopupMenu();
    AppendMenuW(popup, MF_STRING, Copy, L"Copy selected rows");
    AppendMenuW(popup, MF_STRING, CopyCell, L"Copy cell");
    AppendMenuW(popup, MF_STRING, SelectAll, L"Select all");
    enableMenu(popup, Copy, ListView_GetSelectedCount(table_) != 0);
    enableMenu(popup, CopyCell, contextRow_ >= 0 && contextColumn_ >= 0);
    enableMenu(popup, SelectAll, model_.size() != 0);
    const UINT selected = TrackPopupMenu(popup, TPM_RETURNCMD | TPM_RIGHTBUTTON, point.x, point.y,
                                         0, window_, nullptr);
    DestroyMenu(popup);
    if (selected)
        command(WORD(selected));
}

void InspectorWindow::error(const std::wstring& message, const wchar_t* title) {
    MessageBoxW(window_, message.c_str(), title, MB_OK | MB_ICONERROR);
}

void InspectorWindow::command(WORD id) {
    if (id >= FirstPage && id < FirstPage + pageCount) {
        setPage(Page(id - FirstPage));
        return;
    }
    switch (id) {
    case Open:
        openDialog();
        break;
    case Reload:
        if (image_ && !loading_)
            beginLoad(image_->path);
        break;
    case Save:
        saveDialog();
        break;
    case CloseFile:
        closeFile();
        break;
    case Exit:
        SendMessageW(window_, WM_CLOSE, 0, 0);
        break;
    case Copy:
        copySelection();
        break;
    case CopyCell:
        if (contextRow_ >= 0 && size_t(contextRow_) < model_.size()) {
            const auto& cells = model_.row(size_t(contextRow_)).cells;
            if (contextColumn_ >= 0 && size_t(contextColumn_) < cells.size())
                copyToClipboard(cells[size_t(contextColumn_)].text);
        }
        break;
    case CopyHash:
        if (image_)
            copyToClipboard(pe::wide(image_->sha256));
        break;
    case SelectAll:
        SetFocus(table_);
        ListView_SetItemState(table_, -1, LVIS_SELECTED, LVIS_SELECTED);
        break;
    case Find:
        if (image_) {
            SetFocus(filter_);
            SendMessageW(filter_, EM_SETSEL, 0, -1);
        }
        break;
    case ClearFilter:
        KillTimer(window_, filterTimer);
        SetWindowTextW(filter_, L"");
        setFilter();
        break;
    case About:
        MessageBoxW(window_,
                    (L"DLL Explorer " + pe::wide(pe::Version) +
                     L"\n\nPortable Executable inspector for Windows.\nC++ / native Win32"
                     L"\n\nFiles are read as data and are never executed.")
                        .c_str(),
                    L"About DLL Explorer", MB_OK | MB_ICONINFORMATION);
        break;
    default:
        break;
    }
}

LRESULT InspectorWindow::onNotify(NMHDR* notification) {
    if (notification->hwndFrom == tabs_ && notification->code == TCN_SELCHANGE) {
        setPage(Page(TabCtrl_GetCurSel(tabs_)));
        return 0;
    }
    if (notification->hwndFrom != table_)
        return 0;
    switch (notification->code) {
    case LVN_GETDISPINFOW: {
        auto* info = reinterpret_cast<NMLVDISPINFOW*>(notification);
        if (!(info->item.mask & LVIF_TEXT))
            return 0;
        info->item.pszText = const_cast<wchar_t*>(L"");
        if (info->item.iItem < 0 || size_t(info->item.iItem) >= model_.size())
            return 0;
        const auto& cells = model_.row(size_t(info->item.iItem)).cells;
        if (info->item.iSubItem >= 0 && size_t(info->item.iSubItem) < cells.size())
            info->item.pszText =
                const_cast<wchar_t*>(cells[size_t(info->item.iSubItem)].text.c_str());
        return 0;
    }
    case LVN_GETEMPTYMARKUP: {
        auto* markup = reinterpret_cast<NMLVEMPTYMARKUP*>(notification);
        markup->dwFlags = EMF_CENTERED;
        const wchar_t* message = !image_ ? L"Open a DLL or EXE (Ctrl+O), or drop a file here."
                                 : !currentFilter_.empty() ? L"No rows match the filter."
                                 : page_ == Page::Warnings ? L"No parser warnings were reported."
                                 : page_ == Page::Exports  ? L"This binary has no exported symbols."
                                 : page_ == Page::Imports  ? L"This binary has no listed imports."
                                                           : L"No entries.";
        wcsncpy_s(markup->szMarkup, message, _TRUNCATE);
        return TRUE;
    }
    case LVN_COLUMNCLICK: {
        const auto* clicked = reinterpret_cast<NMLISTVIEW*>(notification);
        if (clicked->iSubItem >= 0)
            sortByColumn(size_t(clicked->iSubItem));
        return 0;
    }
    case LVN_ITEMCHANGED:
        updateActions();
        return 0;
    case NM_DBLCLK:
        copySelection();
        return 0;
    case LVN_KEYDOWN: {
        const auto* key = reinterpret_cast<NMLVKEYDOWN*>(notification);
        if (key->wVKey == 'C' && (GetKeyState(VK_CONTROL) & 0x8000))
            copySelection();
        if (key->wVKey == 'A' && (GetKeyState(VK_CONTROL) & 0x8000))
            command(SelectAll);
        return 0;
    }
    default:
        return 0;
    }
}

LRESULT InspectorWindow::dispatch(UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        return createControls() ? 0 : -1;
    case WM_SIZE:
        layout();
        return 0;
    case WM_GETMINMAXINFO: {
        MONITORINFO monitor{sizeof(monitor)};
        GetMonitorInfoW(MonitorFromWindow(window_, MONITOR_DEFAULTTONEAREST), &monitor);
        const int availableWidth = int(monitor.rcWork.right - monitor.rcWork.left);
        const int availableHeight = int(monitor.rcWork.bottom - monitor.rcWork.top);
        reinterpret_cast<MINMAXINFO*>(lParam)->ptMinTrackSize = {
            std::min(px(850), availableWidth), std::min(px(540), availableHeight)};
        return 0;
    }
    case WM_DPICHANGED: {
        applyDpi(HIWORD(wParam));
        const auto* bounds = reinterpret_cast<RECT*>(lParam);
        SetWindowPos(window_, nullptr, bounds->left, bounds->top, bounds->right - bounds->left,
                     bounds->bottom - bounds->top, SWP_NOZORDER | SWP_NOACTIVATE);
        refreshTable(true);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == FilterId && HIWORD(wParam) == EN_CHANGE) {
            SetTimer(window_, filterTimer, 120, nullptr);
            return 0;
        }
        if (LOWORD(wParam) == ClearId)
            command(ClearFilter);
        else
            command(LOWORD(wParam));
        return 0;
    case WM_NOTIFY:
        return onNotify(reinterpret_cast<NMHDR*>(lParam));
    case WM_INITMENUPOPUP:
        updateActions();
        return 0;
    case WM_TIMER:
        if (wParam == filterTimer) {
            KillTimer(window_, filterTimer);
            setFilter();
        }
        if (wParam == statusTimer) {
            KillTimer(window_, statusTimer);
            updateStatus();
        }
        return 0;
    case WM_DROPFILES: {
        HDROP drop = HDROP(wParam);
        const UINT length = DragQueryFileW(drop, 0, nullptr, 0);
        std::wstring path(size_t(length) + 1, L'\0');
        DragQueryFileW(drop, 0, path.data(), length + 1);
        DragFinish(drop);
        path.resize(length);
        if (!path.empty())
            beginLoad(path);
        return 0;
    }
    case WM_CONTEXTMENU:
        if (HWND(wParam) == table_)
            showContextMenu(lParam);
        else
            return DefWindowProcW(window_, message, wParam, lParam);
        return 0;
    case WM_CTLCOLORSTATIC:
        if (HWND(lParam) == path_) {
            SetTextColor(HDC(wParam), GetSysColor(COLOR_WINDOWTEXT));
            SetBkColor(HDC(wParam), GetSysColor(COLOR_WINDOW));
            return LRESULT(GetSysColorBrush(COLOR_WINDOW));
        }
        break;
    case loadCompleted:
        finishLoad();
        return 0;
    case WM_CLOSE:
        DestroyWindow(window_);
        return 0;
    case WM_DESTROY:
        stopWorker();
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(window_, message, wParam, lParam);
}

LRESULT CALLBACK InspectorWindow::windowProc(HWND window, UINT message, WPARAM wParam,
                                             LPARAM lParam) noexcept {
    auto* self = reinterpret_cast<InspectorWindow*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* creation = reinterpret_cast<CREATESTRUCTW*>(lParam);
        self = static_cast<InspectorWindow*>(creation->lpCreateParams);
        self->window_ = window;
        SetWindowLongPtrW(window, GWLP_USERDATA, LONG_PTR(self));
    }
    if (!self)
        return DefWindowProcW(window, message, wParam, lParam);
    try {
        const auto result = self->dispatch(message, wParam, lParam);
        if (message == WM_NCDESTROY) {
            SetWindowLongPtrW(window, GWLP_USERDATA, 0);
            self->window_ = nullptr;
        }
        return result;
    } catch (const std::exception& failure) {
        std::wstring text;
        try {
            text = pe::wide(failure.what());
        } catch (...) {
            text = L"Not enough memory to complete this operation.";
        }
        MessageBoxW(window, text.c_str(), L"DLL Explorer", MB_OK | MB_ICONERROR);
        return message == WM_CREATE ? -1 : 0;
    } catch (...) {
        MessageBoxW(window, L"The operation could not be completed.", L"DLL Explorer",
                    MB_OK | MB_ICONERROR);
        return message == WM_CREATE ? -1 : 0;
    }
}

int InspectorWindow::run(const std::filesystem::path& initialFile) {
    INITCOMMONCONTROLSEX controls{sizeof(controls),
                                  ICC_BAR_CLASSES | ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES};
    if (!InitCommonControlsEx(&controls))
        throw pe::Error("Could not initialize Windows controls.");
    dpi_ = GetDpiForSystem();
    WNDCLASSEXW definition{sizeof(definition)};
    definition.lpfnWndProc = windowProc;
    definition.hInstance = instance_;
    definition.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    definition.hIcon = LoadIconW(instance_, MAKEINTRESOURCEW(1));
    definition.hIconSm = definition.hIcon;
    definition.hbrBackground = GetSysColorBrush(COLOR_BTNFACE);
    definition.lpszClassName = className;
    if (!RegisterClassExW(&definition) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        throw pe::Error("Could not register the inspector window.");
    createAccelerators();
    HMENU menu = createMenus();
    RECT bounds{0, 0, px(1140), px(740)};
    AdjustWindowRectExForDpi(&bounds, WS_OVERLAPPEDWINDOW, TRUE, 0, dpi_);
    RECT workArea{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
    const int initialWidth =
        std::min(int(bounds.right - bounds.left),
                 std::max(px(600), int(workArea.right - workArea.left) - px(24)));
    const int initialHeight =
        std::min(int(bounds.bottom - bounds.top),
                 std::max(px(400), int(workArea.bottom - workArea.top) - px(24)));
    window_ = CreateWindowExW(WS_EX_CONTROLPARENT | WS_EX_ACCEPTFILES, className, L"DLL Explorer",
                              WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT,
                              initialWidth, initialHeight, nullptr, menu, instance_, this);
    if (!window_) {
        DestroyMenu(menu);
        throw pe::Error("Could not create the inspector window.");
    }
    ShowWindow(window_, SW_SHOW);
    UpdateWindow(window_);
    if (!initialFile.empty())
        beginLoad(initialFile);
    MSG message{};
    BOOL received = 0;
    while ((received = GetMessageW(&message, nullptr, 0, 0)) > 0) {
        if (message.message == WM_KEYDOWN && message.wParam == VK_ESCAPE &&
            (message.hwnd == filter_ || message.hwnd == table_)) {
            command(ClearFilter);
            continue;
        }
        if (TranslateAcceleratorW(window_, accelerators_, &message))
            continue;
        if (!IsDialogMessageW(window_, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    if (received == -1)
        throw pe::Error("The Windows message loop failed.");
    return int(message.wParam);
}
} // namespace ui
