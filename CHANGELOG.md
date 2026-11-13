# Changelog

All notable changes to `pe-parse` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

All versions prior to [2.0.0] are untracked.

## [Unreleased]

### Fixed

- Reject malformed PE section, symbol, resource, import, export, relocation,
  and debug table counts or ranges before allocating or iterating over
  attacker-controlled entries. Table sizes are checked against the actual
  file and section bounds with overflow-safe address arithmetic. File-backed
  buffers now reject files larger than the parser's 32-bit address space.

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
