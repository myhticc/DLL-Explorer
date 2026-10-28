# DLL Explorer

A portable Windows utility for inspecting DLLs and other Portable Executable files.
Written in C++17 with native Win32 controls. English interface; no installer or
additional runtime required.

## Inspector

Open **DLLExplorer.exe** and choose a binary, or drag a file onto the window.

| View | Contents |
| --- | --- |
| Overview | File properties, machine type, PE headers, flags and SHA-256 |
| Dependencies | Declared libraries, symbol counts and standard/delayed load modes |
| Imports | Functions, libraries, hints and ordinal imports |
| Exports | Named/ordinal exports, RVAs and forwarders |
| Sections | Virtual addresses, file offsets, sizes and access flags |
| Warnings | Diagnostics for incomplete or malformed directories |

Every view supports case-insensitive filtering. Click a column header to sort;
addresses, sizes and ordinals sort numerically. Columns can be resized.
Select multiple rows and copy them, or right-click to copy a single cell.
Save a complete report as UTF-8 JSON or text.

| Shortcut | Action |
| --- | --- |
| Ctrl+O | Open binary |
| F5 | Reload current binary |
| Ctrl+S | Save report |
| Ctrl+W | Close current binary / cancel loading |
| Ctrl+F | Focus filter |
| Ctrl+1 through Ctrl+6 | Switch view |
| Ctrl+A, with table focus | Select all visible rows |
| Ctrl+C, with table focus | Copy selected rows |
| Escape, with filter/table focus | Clear filter |

Double-click a row to copy the current selection.

## Requirements and scope

Windows 10 version 1607 or later, or Windows 11, x64. The C++ runtime is linked
statically. The x64 application inspects both PE32 and PE32+ files.

The app reads files as bytes; it never loads or executes an inspected binary.
It makes no network requests. Imports describe declared dependencies; the app
does not recursively resolve DLL search paths, disassemble instructions, inspect
managed methods or verify Authenticode signatures. The certificate field only
indicates a file-backed certificate table. Header flags describe declarations.
COFF timestamps are shown as raw values because they need not represent build dates.

Files are limited to 512 MB, 250,000 imported/exported symbols and a 64 MB symbol-text
budget. Invalid core headers are rejected. Recoverable import/export errors leave
partial results and explicit warnings. Report writes use a temporary file and an
atomic replacement; the source binary cannot be selected as a report destination.

## Source organization

- **src/core/parser.cpp** — checked PE reads, RVA mapping, imports/exports and SHA-256.
- **src/core/io.cpp** — consistent file snapshots, cancellation, UTF conversions and atomic saves.
- **src/core/report.cpp** — versioned JSON and text serialization.
- **src/ui/model.cpp** — table schemas, filtering, typed sorting and copy formatting.
- **src/ui/window.cpp** — native window/controller and an owned, cancellable loading thread.
- **tests/** — deterministic parser fixtures, malformed inputs, mutation cases,
  real Windows binaries, view-model tests and CLI/report regressions.

## Build and test

Install Visual Studio 2022 / Build Tools with **Desktop development with C++** and
a Windows 10 or 11 SDK. Then, from the project directory:

~~~powershell
.\build.ps1 -Tests
.\tests\integration_tests.ps1
~~~

The standalone executable is **build/DLLExplorer.exe**.
Builds use **/W4 /WX**, static CRT, Control Flow Guard, DEP and ASLR.
The script restores the calling process's toolchain environment on completion.

Optional analysis builds:

~~~powershell
.\build.ps1 -Tests -Analyze
.\build.ps1 -Tests -Sanitize -OutputDirectory .\build\asan
~~~

AddressSanitizer is for development and requires the corresponding Visual Studio
component. Its binaries are not the portable release.

CMake is also supported:

~~~powershell
cmake -S . -B build/cmake -A x64
cmake --build build/cmake --config Release
ctest --test-dir build/cmake -C Release --output-on-failure
~~~

The included GitHub Actions workflow runs static analysis and tests on Windows.

## Command line

~~~text
DLLExplorer.exe --inspect "C:\Windows\System32\version.dll" "report.json"
~~~

This mode writes JSON without opening the GUI. Exit codes:
**0** success, **2** invalid/unreadable input (error JSON is written),
**3** report write failure, **64** invalid command-line arguments.

PE parsing follows the [Microsoft PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
