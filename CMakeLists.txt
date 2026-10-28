cmake_minimum_required(VERSION 3.21)
project(DLLExplorer VERSION 1.1.0 LANGUAGES CXX RC)

if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "DLL Explorer requires Windows and the MSVC toolchain.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Build the application for x64. It can inspect both x86 and x64 files.")
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
option(DLL_EXPLORER_TESTS "Build parser and view-model tests" ON)
option(DLL_EXPLORER_ASAN "Enable AddressSanitizer" OFF)

add_library(project_options INTERFACE)
target_compile_features(project_options INTERFACE cxx_std_17)
target_compile_definitions(project_options INTERFACE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
target_compile_options(project_options INTERFACE
    /W4 /WX /utf-8 /EHsc /permissive- /guard:cf /sdl)
if(DLL_EXPLORER_ASAN)
    target_compile_options(project_options INTERFACE /fsanitize=address /Zi)
    target_link_options(project_options INTERFACE /INCREMENTAL:NO)
endif()

add_library(pe_core STATIC src/core/io.cpp src/core/parser.cpp src/core/report.cpp)
target_link_libraries(pe_core PUBLIC project_options bcrypt)

add_library(inspector_model STATIC src/ui/model.cpp)
target_link_libraries(inspector_model PUBLIC pe_core user32)

add_executable(DLLExplorer WIN32 src/main.cpp src/ui/window.cpp assets/app.rc)
target_include_directories(DLLExplorer PRIVATE assets)
target_link_libraries(DLLExplorer PRIVATE inspector_model
    comctl32 comdlg32 shell32 uxtheme gdi32)
target_link_options(DLLExplorer PRIVATE
    /MANIFEST:NO /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /guard:cf /INCREMENTAL:NO)

if(DLL_EXPLORER_TESTS)
    enable_testing()
    add_executable(parser_tests tests/parser_tests.cpp)
    target_link_libraries(parser_tests PRIVATE pe_core)
    add_test(NAME parser COMMAND parser_tests)
    add_executable(model_tests tests/model_tests.cpp)
    target_link_libraries(model_tests PRIVATE inspector_model)
    add_test(NAME model COMMAND model_tests)
    find_program(POWERSHELL_EXECUTABLE NAMES pwsh powershell REQUIRED)
    add_test(NAME integration COMMAND "${POWERSHELL_EXECUTABLE}" -NoProfile
        -ExecutionPolicy Bypass -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_tests.ps1"
        -Exe "$<TARGET_FILE:DLLExplorer>")
endif()

install(TARGETS DLLExplorer RUNTIME DESTINATION .)
