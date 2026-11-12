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
#include <map>
#include <string>

#include "nt-headers.h"
#include "to_string.h"

#ifdef _MSC_VER
#define __typeof__(x) std::remove_reference<decltype(x)>::type
#endif

namespace peparse {
struct PEDiagnostic;
}

// Legacy error-recording macro. It is retained for source compatibility:
// code (including pe-parse itself) that records an error through PE_ERR keeps
// compiling and keeps populating the legacy, thread-local error state that is
// queried through GetPEErr(), GetPEErrString() and GetPEErrLoc(). New code
// inside the parser uses the per-parse PEDiagnostic machinery instead.
#define PE_ERR(x)               \
  peparse::recordLegacyErr(     \
      static_cast<peparse::pe_err>(x), __func__, __LINE__)

#define READ_WORD(b, o, inst, member)                                          \
  if (!readWord(b,                                                             \
                o + static_cast<uint32_t>(offsetof(__typeof__(inst), member)), \
                inst.member)) {                                                \
    PE_ERR(PEERR_READ);                                                        \
    return false;                                                              \
  }

#define READ_DWORD(b, o, inst, member)                                   \
  if (!readDword(                                                        \
          b,                                                             \
          o + static_cast<uint32_t>(offsetof(__typeof__(inst), member)), \
          inst.member)) {                                                \
    PE_ERR(PEERR_READ);                                                  \
    return false;                                                        \
  }

#define READ_QWORD(b, o, inst, member)                                   \
  if (!readQword(                                                        \
          b,                                                             \
          o + static_cast<uint32_t>(offsetof(__typeof__(inst), member)), \
          inst.member)) {                                                \
    PE_ERR(PEERR_READ);                                                  \
    return false;                                                        \
  }

#define READ_BYTE(b, o, inst, member)                                          \
  if (!readByte(b,                                                             \
                o + static_cast<uint32_t>(offsetof(__typeof__(inst), member)), \
                inst.member)) {                                                \
    PE_ERR(PEERR_READ);                                                        \
    return false;                                                              \
  }

#define TEST_MACHINE_CHARACTERISTICS(h, m, ch) \
  ((h.FileHeader.Machine == m) && (h.FileHeader.Characteristics & ch))

namespace peparse {

typedef std::uint32_t RVA;
typedef std::uint64_t VA;

struct buffer_detail;

typedef struct _bounded_buffer {
  std::uint8_t *buf;
  std::uint32_t bufLen;
  bool copy;
  bool swapBytes;
  buffer_detail *detail;
} bounded_buffer;

struct resource {
  resource()
      : type(0), name(0), lang(0), codepage(0), RVA(0), size(0), buf(nullptr) {
  }

  std::string type_str;
  std::string name_str;
  std::string lang_str;
  std::uint32_t type;
  std::uint32_t name;
  std::uint32_t lang;
  std::uint32_t codepage;
  std::uint32_t RVA;
  std::uint32_t size;
  bounded_buffer *buf;
};

#ifndef _PEPARSE_WINDOWS_CONFLICTS
// http://msdn.microsoft.com/en-us/library/ms648009(v=vs.85).aspx
enum resource_type {
  RT_CURSOR = 1,
  RT_BITMAP = 2,
  RT_ICON = 3,
  RT_MENU = 4,
  RT_DIALOG = 5,
  RT_STRING = 6,
  RT_FONTDIR = 7,
  RT_FONT = 8,
  RT_ACCELERATOR = 9,
  RT_RCDATA = 10,
  RT_MESSAGETABLE = 11,
  RT_GROUP_CURSOR = 12, // MAKEINTRESOURCE((ULONG_PTR)(RT_CURSOR) + 11)
  RT_GROUP_ICON = 14,   // MAKEINTRESOURCE((ULONG_PTR)(RT_ICON) + 11)
  RT_VERSION = 16,
  RT_DLGINCLUDE = 17,
  RT_PLUGPLAY = 19,
  RT_VXD = 20,
  RT_ANICURSOR = 21,
  RT_ANIICON = 22,
  RT_HTML = 23,
  RT_MANIFEST = 24
};
#endif

enum pe_err {
  PEERR_NONE = 0,
  PEERR_MEM = 1,
  PEERR_HDR = 2,
  PEERR_SECT = 3,
  PEERR_RESC = 4,
  PEERR_SECTVA = 5,
  PEERR_READ = 6,
  PEERR_OPEN = 7,
  PEERR_STAT = 8,
  PEERR_MAGIC = 9,
  PEERR_BUFFER = 10,
  PEERR_ADDRESS = 11,
  PEERR_SIZE = 12,
};

// High-level phase of a ParsePEFrom* call. A failure always belongs to
// exactly one stage, which lets callers distinguish e.g. a corrupt header
// from a corrupt data directory without parsing source file locations.
enum pe_parse_stage {
  PE_STAGE_NONE = 0,
  PE_STAGE_FILE_OPEN,
  PE_STAGE_BUFFER,
  PE_STAGE_DOS_HEADER,
  PE_STAGE_RICH_HEADER,
  PE_STAGE_NT_HEADERS,
  PE_STAGE_SECTIONS,
  PE_STAGE_RESOURCES,
  PE_STAGE_EXPORTS,
  PE_STAGE_RELOCATIONS,
  PE_STAGE_DEBUG,
  PE_STAGE_IMPORTS,
  PE_STAGE_SYMBOL_TABLE,
};

// Structured diagnostic for a single ParsePEFrom* invocation.
//
// One PEDiagnostic instance is used by exactly one parse call: concurrent
// parses on different threads and nested parses on the same thread each have
// their own instance and never overwrite each other. The fields are reset to
// their default values at the start of every parse call. Within a single
// call each failure site overwrites the previous record, so an outer stage
// can mask a low-level read error with a broader error code just like the
// legacy GetPEErr() interface.
//
// Call contract:
//   * On a successful parse the returned parsed_pe pointer is non-null and
//     code == PEERR_NONE. All existing parsed_pe accessors keep their
//     existing behavior.
//   * On a failed parse the returned parsed_pe pointer is null and code holds
//     the pe_err value recorded at the failure site, with the stage,
//     directory (when the failure happened while processing a data
//     directory) and offset (when associated with a concrete byte offset)
//     filled in. An outer parse stage may re-record a broader error code over
//     the low-level read error reported by a helper, matching the historical
//     behavior of the GetPEErr() interface.
//   * A PEDiagnostic is only meaningful for the parse call it was passed
//     to. It must not be inspected through a parsed_pe object: a failed parse
//     never produces a parsed_pe object, and a successful parse leaves the
//     diagnostic at PEERR_NONE. Iterators and accessors (IterSec, ReadByteAtVA
//     and friends) take a parsed_pe and never touch a PEDiagnostic. Passing
//     nullptr is always valid; in that case the failure remains available
//     through the legacy, thread-local GetPEErr*() interface on the calling
//     thread.
struct PEDiagnostic {
  PEDiagnostic()
      : code(PEERR_NONE),
        stage(PE_STAGE_NONE),
        directory(DIR_RESERVED),
        directoryKnown(false),
        offset(0),
        offsetKnown(false) {
  }

  // pe_err value describing the kind of failure; PEERR_NONE while no failure
  // has been recorded.
  std::uint32_t code;

  // Parser stage that was executing when the failure was recorded.
  pe_parse_stage stage;

  // Data directory being processed when the failure occurred, if any. Only
  // valid when directoryKnown is true. DIR_RESERVED is used as the sentinel
  // value otherwise.
  data_directory_kind directory;
  bool directoryKnown;

  // Byte offset associated with the failure, relative to the buffer being
  // read at the failure site (typically a section or header sub-buffer). Only
  // valid when offsetKnown is true. It identifies where parsing failed, not
  // necessarily the root cause of the malformation.
  std::uint32_t offset;
  bool offsetKnown;

  // Legacy, human-readable "function:line" location of the failure site.
  // Equivalent to the string returned by GetPEErrLoc() for this parse.
  std::string functionLocation;
};

// Record a failure into the calling thread's legacy error state. Used by the
// PE_ERR macro and to mirror per-parse diagnostics for the GetPEErr* API.
void recordLegacyErr(pe_err x, const char *func, std::uint32_t line);

// Stable, human-readable names for pe_parse_stage values. Never returns
// nullptr; unknown values map to "Unknown".
const char *PEParseStageToString(pe_parse_stage stage);

bool readByte(bounded_buffer *b, std::uint32_t offset, std::uint8_t &out);
bool readWord(bounded_buffer *b, std::uint32_t offset, std::uint16_t &out);
bool readDword(bounded_buffer *b, std::uint32_t offset, std::uint32_t &out);
bool readQword(bounded_buffer *b, std::uint32_t offset, std::uint64_t &out);
bool readChar16(bounded_buffer *b, std::uint32_t offset, char16_t &out);

bounded_buffer *readFileToFileBuffer(const char *filePath);
bounded_buffer *makeBufferFromPointer(std::uint8_t *data, std::uint32_t sz);
bounded_buffer *
splitBuffer(bounded_buffer *b, std::uint32_t from, std::uint32_t to);
bounded_buffer *
splitBufferByLength(bounded_buffer *b, std::uint32_t from, std::uint32_t len);
void deleteBuffer(bounded_buffer *b);
uint64_t bufLen(bounded_buffer *b);

struct parsed_pe_internal;

typedef struct _pe_header {
  dos_header dos;
  rich_header rich;
  nt_header_32 nt;
} pe_header;

typedef struct _parsed_pe {
  bounded_buffer *fileBuffer;
  parsed_pe_internal *internal;
  pe_header peHeader;
} parsed_pe;

// Resolve a Rich header product id / build number pair to a known
// product name
typedef std::pair<std::uint16_t, std::uint16_t> ProductKey;
const std::string &GetRichObjectType(std::uint16_t prodId);
const std::string &GetRichProductName(std::uint16_t buildNum);

// get parser error status as integer
//
// Legacy error query interface. These report the most recent failure of a
// ParsePEFrom* call on the *calling thread*: the underlying state is
// thread-local, so concurrent parses on different threads no longer
// interfere with each other. A nested parse on the same thread still updates
// this shared thread state, so code that needs fully isolated diagnostics
// must pass an explicit PEDiagnostic to the ParsePEFrom* entry points.
std::uint32_t GetPEErr();

// get parser error status as string
std::string GetPEErrString();

// get parser error location as string
std::string GetPEErrLoc();

// get a PE parse context from a file
parsed_pe *ParsePEFromFile(const char *filePath);

parsed_pe *ParsePEFromPointer(std::uint8_t *buffer, std::uint32_t sz);
parsed_pe *ParsePEFromBuffer(bounded_buffer *buffer);

// Per-parse, isolated variants of the entry points above. When diagnostic
// is non-null it is reset at the start of the call and populated with
// structured failure information (see PEDiagnostic for the call contract).
// A nullptr diagnostic is valid and yields the legacy behavior, with the
// failure still queryable through GetPEErr*() on the calling thread.
//
// Ownership and the no-object contract:
//   * On success the returned parsed_pe owns the input (the file mapping or
//     the bounded_buffer) and releases it in DestructParsedPE.
//   * On failure these functions always return nullptr: no parsed_pe object
//     is formed, so there is nothing to pass to DestructParsedPE and nothing
//     through which to query a diagnostic. The failure is observable only
//     via the out-parameter PEDiagnostic (when supplied) or the
//     thread-local GetPEErr*() accessors. ParsePEFromBuffer additionally
//     consumes and releases the bounded_buffer on failure, so the caller
//     must not call deleteBuffer on it after a nullptr result.
//   * ParsePEFromFile and ParsePEFromPointer own their intermediate buffer
//     entirely; callers only keep ownership of the raw pointer passed to
//     ParsePEFromPointer, which is never freed by the parser.
parsed_pe *ParsePEFromFile(const char *filePath, PEDiagnostic *diagnostic);
parsed_pe *ParsePEFromPointer(std::uint8_t *buffer,
                              std::uint32_t sz,
                              PEDiagnostic *diagnostic);
parsed_pe *ParsePEFromBuffer(bounded_buffer *buffer,
                             PEDiagnostic *diagnostic);

// destruct a PE context
void DestructParsedPE(parsed_pe *p);

// iterate over Rich header entries
typedef int (*iterRich)(void *, const rich_entry &);
void IterRich(parsed_pe *pe, iterRich cb, void *cbd);

// iterate over the resources
typedef int (*iterRsrc)(void *, const resource &);
void IterRsrc(parsed_pe *pe, iterRsrc cb, void *cbd);

// iterate over the imports by RVA and string
typedef int (*iterVAStr)(void *,
                         const VA &,
                         const std::string &,
                         const std::string &);
void IterImpVAString(parsed_pe *pe, iterVAStr cb, void *cbd);

// iterate over relocations in the PE file
typedef int (*iterReloc)(void *, const VA &, const reloc_type &);
void IterRelocs(parsed_pe *pe, iterReloc cb, void *cbd);

// iterate over debug directories in the PE file
typedef int (*iterDebug)(void *, const std::uint32_t &, const bounded_buffer *);
void IterDebugs(parsed_pe *pe, iterDebug cb, void *cbd);

// Iterate over symbols (symbol table) in the PE file
typedef int (*iterSymbol)(void *,
                          const std::string &,
                          const std::uint32_t &,
                          const std::int16_t &,
                          const std::uint16_t &,
                          const std::uint8_t &,
                          const std::uint8_t &);
void IterSymbols(parsed_pe *pe, iterSymbol cb, void *cbd);

// iterate over the exports, except forwarded exports
typedef int (*iterExp)(void *,
                       const VA &,
                       const std::string &,
                       const std::string &);
void IterExpVA(parsed_pe *pe, iterExp cb, void *cbd);

// iterate over the exports, including forwarded exports
// export ordinal is also provided as the third argument.
// VA will be zero if the current export is forwarded,
// in this case, the last argument (forward string) will be non-empty
typedef int (*iterExpFull)(void *,
                           const VA &,
                           std::uint16_t,
                           const std::string &,
                           const std::string &,
                           const std::string &);
void IterExpFull(parsed_pe *pe, iterExpFull cb, void *cbd);

// iterate over sections
typedef int (*iterSec)(void *,
                       const VA &,
                       const std::string &,
                       const image_section_header &,
                       const bounded_buffer *);
void IterSec(parsed_pe *pe, iterSec cb, void *cbd);

// get byte at VA in PE
bool ReadByteAtVA(parsed_pe *pe, VA v, std::uint8_t &b);

// get entry point into PE
bool GetEntryPoint(parsed_pe *pe, VA &v);

// get machine as human readable string
const char *GetMachineAsString(parsed_pe *pe);

// get subsystem as human readable string
const char *GetSubsystemAsString(parsed_pe *pe);

// get a table or string by its data directory entry
bool GetDataDirectoryEntry(parsed_pe *pe,
                           data_directory_kind dirnum,
                           std::vector<std::uint8_t> &raw_entry);
} // namespace peparse
