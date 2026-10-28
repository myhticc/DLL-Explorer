#include "pe.hpp"
#include "ui/window.hpp"
#include <shellapi.h>

namespace {
int inspect(const std::filesystem::path& input, const std::filesystem::path& output) {
    std::string content;
    int result = 0;
    try {
        content = pe::json(pe::load(input));
    } catch (const std::exception& failure) {
        content = "{\"error\": " + pe::jsonEscape(failure.what()) + "}\n";
        result = 2;
    }
    try {
        pe::writeReport(output, content, input);
    } catch (...) {
        return 3;
    }
    return result;
}
} // namespace

int WINAPI wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE, _In_ PWSTR, _In_ int) {
    int count = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &count);
    if (!arguments)
        return 1;
    struct FreeArguments {
        LPWSTR* value;
        ~FreeArguments() {
            LocalFree(value);
        }
    } cleanup{arguments};
    try {
        if (count == 4 && std::wstring(arguments[1]) == L"--inspect")
            return inspect(arguments[2], arguments[3]);
        if (count > 2 || (count == 2 && std::wstring(arguments[1]).rfind(L"--", 0) == 0))
            return 64;
        ui::InspectorWindow application(instance);
        return application.run(count == 2 ? std::filesystem::path(arguments[1])
                                          : std::filesystem::path{});
    } catch (const std::exception& failure) {
        MessageBoxW(nullptr, pe::wide(failure.what()).c_str(), L"DLL Explorer",
                    MB_OK | MB_ICONERROR);
        return 1;
    }
}
