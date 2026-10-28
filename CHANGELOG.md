# Changelog

## 1.1.0

- Replace the custom dark dashboard with native Windows menus, toolbar, tabs,
  status bar and compact, resizable tables.
- Add a dedicated dependency list and parser diagnostics view.
- Allow filtering every view, selecting multiple rows, copying a cell, reloading
  a file and navigating tabs with keyboard shortcuts.
- Split parsing, file I/O, report serialization, table models and window control.
- Replace the detached loading thread with an owned, cancellable worker.
- Preserve dependencies that import no recoverable symbols.
- Support legacy VA-based delay import tables.
- Bound forwarded export strings to their directory and enforce total export limits.
- Save reports atomically; refuse to overwrite the inspected binary.
- Add view-model, cancellation, malformed-directory and report regression tests.
- Add warning-clean builds, optional static analysis and AddressSanitizer, CMake,
  formatting rules and build instructions.
