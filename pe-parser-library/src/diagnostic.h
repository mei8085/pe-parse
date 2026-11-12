/*
The MIT License (MIT)

Copyright (c) 2013 Andrew Ruef

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#pragma once

#include <cstdint>
#include <string>

#include <pe-parse/nt-headers.h>
#include <pe-parse/parse.h>
#include <pe-parse/to_string.h>

namespace peparse {

// Legacy error state, made thread-local so that concurrent ParsePE* calls on
// different threads do not clobber each other. Each ParsePE* call also
// produces a fully isolated PEDiagnostic; the state below only mirrors the
// most recent failure on the calling thread for the legacy GetPEErr*() API.
extern thread_local std::uint32_t tls_err;
extern thread_local std::string tls_err_loc;

// The PEDiagnostic of the ParsePEFrom* call currently executing on this
// thread, or nullptr outside of a parse. Defined in buffer.cpp so that the
// bounded buffer readers can attach failing offsets to it.
extern thread_local PEDiagnostic *active_diagnostic;

// RAII guard that binds a PEDiagnostic to the calling thread for the duration
// of a parse, restoring the previous binding on destruction. This is what
// makes nested parses safe: an inner parse saves and restores the outer
// parse's binding instead of clobbering it.
struct ActiveDiagnosticGuard {
  explicit ActiveDiagnosticGuard(PEDiagnostic *diag)
      : previous(active_diagnostic) {
    active_diagnostic = diag;
  }

  ~ActiveDiagnosticGuard() {
    active_diagnostic = previous;
  }

  ActiveDiagnosticGuard(const ActiveDiagnosticGuard &) = delete;
  ActiveDiagnosticGuard &operator=(const ActiveDiagnosticGuard &) = delete;

  PEDiagnostic *previous;
};

// Record a failure into the per-parse diagnostic and mirror it into the
// calling thread's legacy error state.
//
//   x     : a pe_err value
//   diag  : the PEDiagnostic owned by the in-flight ParsePE* call
//   func  : the function that detected the failure (__func__)
//   line  : the source line that detected the failure (__LINE__)
//   off   : the byte offset associated with the failure, if known
//   known : whether off is meaningful
//
// Every failure site overwrites the previous record. This preserves the
// historical error-masking behavior: an outer parse stage re-records a
// broader error code (e.g. PEERR_SECT) over the low-level read error
// (e.g. PEERR_READ) reported by the bounded buffer layer.
inline void recordDiag(pe_err x,
                       PEDiagnostic &diag,
                       const char *func,
                       std::uint32_t line,
                       std::uint32_t off,
                       bool known) {
  diag.code = static_cast<std::uint32_t>(x);

  std::string loc(func);
  loc += ":";
  loc += to_string<std::uint32_t>(line, std::dec);
  diag.functionLocation = loc;

  diag.offsetKnown = known;
  if (known) {
    diag.offset = off;
  }

  // Mirror into the legacy, thread-local error state.
  tls_err = diag.code;
  tls_err_loc = loc;
}

// Reset the per-parse diagnostic (and the calling thread's legacy state) at
// the start of every ParsePE* call, so a fresh parse never inherits
// diagnostics from a previous, possibly nested, parse.
inline void resetDiag(PEDiagnostic &diag) {
  diag.code = PEERR_NONE;
  diag.stage = PE_STAGE_NONE;
  diag.directory = DIR_RESERVED;
  diag.directoryKnown = false;
  diag.offset = 0;
  diag.offsetKnown = false;
  diag.functionLocation.clear();

  tls_err = PEERR_NONE;
  tls_err_loc.clear();
}

} // namespace peparse

// Structured, per-parse replacement for the legacy PE_ERR macro. All failure
// sites inside the parser route through here. Each call overwrites the
// previous record so that outer-stage error masking is preserved.
#define PE_DIAG(x, d)                                                          \
  do {                                                                         \
    peparse::recordDiag(static_cast<peparse::pe_err>(x),                       \
                        (d),                                                   \
                        __func__,                                              \
                        static_cast<std::uint32_t>(__LINE__),                  \
                        0,                                                     \
                        false);                                                \
  } while (0)

// Like PE_DIAG, but also records the byte offset associated with the failure.
#define PE_DIAG_AT(x, d, off)                                                  \
  do {                                                                         \
    peparse::recordDiag(static_cast<peparse::pe_err>(x),                       \
                        (d),                                                   \
                        __func__,                                              \
                        static_cast<std::uint32_t>(__LINE__),                  \
                        static_cast<std::uint32_t>(off),                       \
                        true);                                                 \
  } while (0)

// Internal READ_* macros. They behave like the legacy READ_* macros in
// parse.h, but record into the per-parse diagnostic and capture the offset
// that failed to read.
#define READ_WORD_DIAG(b, o, inst, member, d)                                  \
  if (!readWord(b,                                                             \
                o + static_cast<uint32_t>(offsetof(__typeof__(inst), member)), \
                inst.member)) {                                                \
    PE_DIAG_AT(PEERR_READ, d,                                                  \
               o + static_cast<uint32_t>(offsetof(__typeof__(inst), member))); \
    return false;                                                              \
  }

#define READ_DWORD_DIAG(b, o, inst, member, d)                                 \
  if (!readDword(                                                              \
          b,                                                                   \
          o + static_cast<uint32_t>(offsetof(__typeof__(inst), member)),       \
          inst.member)) {                                                      \
    PE_DIAG_AT(PEERR_READ, d,                                                  \
               o + static_cast<uint32_t>(offsetof(__typeof__(inst), member))); \
    return false;                                                              \
  }

#define READ_QWORD_DIAG(b, o, inst, member, d)                                 \
  if (!readQword(                                                              \
          b,                                                                   \
          o + static_cast<uint32_t>(offsetof(__typeof__(inst), member)),       \
          inst.member)) {                                                      \
    PE_DIAG_AT(PEERR_READ, d,                                                  \
               o + static_cast<uint32_t>(offsetof(__typeof__(inst), member))); \
    return false;                                                              \
  }

#define READ_BYTE_DIAG(b, o, inst, member, d)                                  \
  if (!readByte(b,                                                             \
                o + static_cast<uint32_t>(offsetof(__typeof__(inst), member)), \
                inst.member)) {                                                \
    PE_DIAG_AT(PEERR_READ, d,                                                  \
               o + static_cast<uint32_t>(offsetof(__typeof__(inst), member))); \
    return false;                                                              \
  }
