# Changelog

All notable changes to `pe-parse` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

All versions prior to [2.0.0] are untracked.

## [Unreleased]

### Added

- Added per-parse, structured diagnostics (`PEDiagnostic`) to the
  `ParsePEFromFile`, `ParsePEFromPointer`, and `ParsePEFromBuffer` entry
  points via an optional out-parameter. A failed parse now reports a stable
  error code together with the failing parser stage, the data directory being
  processed (when applicable), and the failing byte offset (when known).
- Added `PEParseStageToString()` for stable, human-readable parser stage
  names.

### Changed

- Parse diagnostics are now isolated per call: concurrent parses on
  different threads and nested parses on the same thread no longer overwrite
  each other's failure information.
- The legacy `GetPEErr()`, `GetPEErrString()`, and `GetPEErrLoc()` error
  query interface is preserved and is now thread-local instead of
  process-global. The legacy `PE_ERR` and `READ_*` macros are retained for
  source compatibility.
- Documented the no-object call contract: a failed parse always returns
  `nullptr` (no `parsed_pe` object is formed), with the failure observable
  through the out-parameter diagnostic or the thread-local accessors, and
  `ParsePEFromBuffer` consumes the input buffer on failure.

## [3.0.0-rc.1] - 2026-05-22

### Added

- Added PEP 517 and `pyproject.toml` build support for `pepy`. (#211)
- Added additional PE machine and relocation constants, including LoongArch,
  PowerPC big-endian, SH3E, ARM/Thumb, and RISC-V values. (#193)

### Changed

- Non-Windows builds now use and require ICU for UTF-16 conversion. (#210)
- Documented the error handling thread-safety limitation.

### Removed

- Removed `pepy` support for Python 3.7, 3.8, and 3.9. (#179, #211)

### Fixed

- Fixed malformed debug directory handling so parsing skips invalid debug data
  instead of failing the whole PE parse. (#199)
- Fixed Windows UTF-16 conversion buffer sizing. (#213)
- Fixed Windows file open and size failure paths to set `PEERR_OPEN`. (#200)
- Fixed missing C++ source files in Python source distributions. (#184)
- Corrected several PE machine constant values. (#193)

<!-- Release URLs -->
[Unreleased]: https://github.com/trailofbits/pe-parse/compare/v3.0.0-rc.1...HEAD
[3.0.0-rc.1]: https://github.com/trailofbits/pe-parse/compare/v2.1.1...v3.0.0-rc.1
[2.1.1]: https://github.com/trailofbits/pe-parse/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/trailofbits/pe-parse/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/trailofbits/pe-parse/compare/v1.3.0...v2.0.0
