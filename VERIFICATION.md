# Release verification — 1.1.0

Date: 2026-10-28

## Completed locally

- Native x64 release build: MSVC 19.44 / Windows SDK 10.0.26100.
- /W4 /WX build and MSVC /analyze: passed without warnings.
- Parser tests: 2,868 assertions, including PE32/PE32+, named/ordinal imports,
  standard/legacy delay loads, forwarded exports, malformed/null addresses,
  cancellation, text escaping, real Windows binaries and 1,800 mutation cases.
- View-model tests: 62 assertions, including table schemas, dependency grouping,
  filtering, numeric sorting, copy formatting and a 30,000-row table.
- AddressSanitizer: parser and view-model tests passed without reported errors.
- Independent CMake Release build: passed. CTest: 3/3 groups passed.
- CLI/report integration: Unicode paths, JSON validity, SHA-256 comparison with
  Windows, invalid/missing/locked inputs, input overwrite protection, failed
  atomic replacement, old-report preservation, temporary cleanup and exit codes.
- C++ formatting and PowerShell syntax checks: passed.
- Release imports: Windows libraries only; no Java, MSVC runtime redistributable
  or AddressSanitizer runtime dependency.
- Release headers: x64 Windows GUI, CFG, DEP, ASLR and high-entropy VA enabled.

## Validation scope

No desktop automation, screenshot capture or GUI interaction testing was used
for this revision. Native control layout and event handling were reviewed in code;
table behavior was tested independently of the window. The included GitHub
Actions workflow has not been run on a remote repository.

These checks cover the exercised cases; they are not a guarantee for every
possible malformed binary or Windows configuration.
