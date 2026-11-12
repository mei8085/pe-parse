#include <pe-parse/parse.h>

#include <array>
#include <atomic>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "catch2/catch.hpp"
#include "filesystem_compat.h"

namespace peparse {

namespace {

std::vector<std::uint8_t> readAll(const std::string &path) {
  FILE *f = fopen(path.c_str(), "rb");
  REQUIRE(f != nullptr);
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  std::vector<std::uint8_t> data(static_cast<std::size_t>(sz));
  REQUIRE(fread(data.data(), 1, data.size(), f) == data.size());
  fclose(f);
  return data;
}

} // namespace

TEST_CASE("successful parse leaves a clean diagnostic", "[diagnostic]") {
  auto path = fs::path(ASSETS_DIR) / "example.exe";
  auto bytes = readAll(path.string());

  PEDiagnostic diag;
  parsed_pe *pe =
      ParsePEFromPointer(bytes.data(),
                         static_cast<std::uint32_t>(bytes.size()),
                         &diag);

  REQUIRE(pe != nullptr);
  REQUIRE(diag.code == PEERR_NONE);
  REQUIRE(diag.stage == PE_STAGE_NONE);
  REQUIRE(diag.offsetKnown == false);
  REQUIRE(diag.directoryKnown == false);
  REQUIRE(diag.functionLocation.empty());

  // Existing structure access keeps working unchanged.
  VA entry = 0;
  REQUIRE(GetEntryPoint(pe, entry));
  REQUIRE(entry != 0);
  REQUIRE(GetMachineAsString(pe) != nullptr);

  DestructParsedPE(pe);
}

TEST_CASE("a malformed PE yields a structured diagnostic", "[diagnostic]") {
  auto path = fs::path(ASSETS_DIR) / "pr_153.exe";
  auto bytes = readAll(path.string());

  PEDiagnostic diag;
  parsed_pe *pe =
      ParsePEFromPointer(bytes.data(),
                         static_cast<std::uint32_t>(bytes.size()),
                         &diag);

  REQUIRE(pe == nullptr);
  REQUIRE(diag.code == PEERR_MAGIC);
  REQUIRE_FALSE(diag.functionLocation.empty());
  REQUIRE(PEParseStageToString(diag.stage) != nullptr);
  REQUIRE(std::string(PEParseStageToString(diag.stage)) != "Unknown");

  // The legacy interface reports the same error code on this thread.
  REQUIRE(GetPEErr() == PEERR_MAGIC);
  REQUIRE(GetPEErrString() == "Bad magic");
  REQUIRE(GetPEErrLoc() == diag.functionLocation);
}

TEST_CASE("truncated input records a stage and an offset", "[diagnostic]") {
  auto path = fs::path(ASSETS_DIR) / "example.exe";
  auto bytes = readAll(path.string());

  // Cut the image down to a tiny fragment: the DOS header parses, but the NT
  // headers cannot be read.
  bytes.resize(64);

  PEDiagnostic diag;
  parsed_pe *pe =
      ParsePEFromPointer(bytes.data(),
                         static_cast<std::uint32_t>(bytes.size()),
                         &diag);

  REQUIRE(pe == nullptr);
  REQUIRE(diag.code != PEERR_NONE);
  REQUIRE((diag.stage == PE_STAGE_NT_HEADERS ||
           diag.stage == PE_STAGE_DOS_HEADER ||
           diag.stage == PE_STAGE_RICH_HEADER));
  // A bounded read failure carries the failing byte offset.
  if (diag.code == PEERR_READ || diag.code == PEERR_ADDRESS) {
    REQUIRE(diag.offsetKnown);
  }
}

TEST_CASE("garbage input fails at the DOS header stage", "[diagnostic]") {
  std::vector<std::uint8_t> bytes(256, 0x41);

  PEDiagnostic diag;
  parsed_pe *pe =
      ParsePEFromPointer(bytes.data(),
                         static_cast<std::uint32_t>(bytes.size()),
                         &diag);

  REQUIRE(pe == nullptr);
  REQUIRE(diag.code == PEERR_MAGIC);
  REQUIRE(diag.stage == PE_STAGE_DOS_HEADER);
}

TEST_CASE("a null diagnostic keeps the legacy behavior", "[diagnostic]") {
  std::vector<std::uint8_t> bytes(256, 0x41);

  parsed_pe *pe = ParsePEFromPointer(
      bytes.data(), static_cast<std::uint32_t>(bytes.size()), nullptr);

  REQUIRE(pe == nullptr);
  REQUIRE(GetPEErr() == PEERR_MAGIC);
  REQUIRE_FALSE(GetPEErrLoc().empty());
}

TEST_CASE("concurrent parses keep isolated diagnostics", "[diagnostic]") {
  auto goodPath = (fs::path(ASSETS_DIR) / "example.exe").string();
  auto badPath = (fs::path(ASSETS_DIR) / "pr_153.exe").string();
  auto goodBytes = readAll(goodPath);
  auto badBytes = readAll(badPath);

  constexpr int kThreads = 8;
  constexpr int kIterations = 200;
  std::atomic<int> mismatches{0};
  std::vector<std::thread> threads;

  for (int t = 0; t < kThreads; ++t) {
    const bool expectBad = (t % 2 == 0);
    threads.emplace_back([&, expectBad]() {
      const auto &bytes = expectBad ? badBytes : goodBytes;
      for (int i = 0; i < kIterations; ++i) {
        PEDiagnostic diag;
        parsed_pe *pe =
            ParsePEFromPointer(const_cast<std::uint8_t *>(bytes.data()),
                               static_cast<std::uint32_t>(bytes.size()),
                               &diag);
        if (expectBad) {
          if (pe != nullptr || diag.code != PEERR_MAGIC) {
            ++mismatches;
          }
        } else {
          if (pe == nullptr || diag.code != PEERR_NONE) {
            ++mismatches;
          }
          DestructParsedPE(pe);
        }
      }
    });
  }

  for (auto &th : threads) {
    th.join();
  }
  REQUIRE(mismatches.load() == 0);
}

TEST_CASE("nested parses do not clobber the outer diagnostic",
          "[diagnostic]") {
  auto goodPath = (fs::path(ASSETS_DIR) / "example.exe").string();
  auto badPath = (fs::path(ASSETS_DIR) / "pr_153.exe").string();
  auto goodBytes = readAll(goodPath);
  auto badBytes = readAll(badPath);

  PEDiagnostic outerDiag;
  parsed_pe *outer =
      ParsePEFromPointer(goodBytes.data(),
                         static_cast<std::uint32_t>(goodBytes.size()),
                         &outerDiag);
  REQUIRE(outer != nullptr);

  // While the outer parsed_pe is alive, run several failing inner parses on
  // the same thread. They must not touch the outer diagnostic nor invalidate
  // the outer parsed_pe.
  for (int i = 0; i < 5; ++i) {
    PEDiagnostic innerDiag;
    parsed_pe *inner =
        ParsePEFromPointer(badBytes.data(),
                           static_cast<std::uint32_t>(badBytes.size()),
                           &innerDiag);
    REQUIRE(inner == nullptr);
    REQUIRE(innerDiag.code == PEERR_MAGIC);

    REQUIRE(outerDiag.code == PEERR_NONE);
    VA entry = 0;
    REQUIRE(GetEntryPoint(outer, entry));
  }

  DestructParsedPE(outer);
}

TEST_CASE("diagnostics are reset between calls on the same instance",
          "[diagnostic]") {
  auto path = fs::path(ASSETS_DIR) / "example.exe";
  auto bytes = readAll(path.string());

  PEDiagnostic diag;

  // First a failing parse populates the diagnostic.
  {
    std::vector<std::uint8_t> garbage(256, 0x41);
    parsed_pe *bad =
        ParsePEFromPointer(garbage.data(),
                           static_cast<std::uint32_t>(garbage.size()),
                           &diag);
    REQUIRE(bad == nullptr);
    REQUIRE(diag.code == PEERR_MAGIC);
  }

  // Reusing the same instance for a successful parse clears it.
  parsed_pe *good =
      ParsePEFromPointer(bytes.data(),
                         static_cast<std::uint32_t>(bytes.size()),
                         &diag);
  REQUIRE(good != nullptr);
  REQUIRE(diag.code == PEERR_NONE);
  REQUIRE(diag.stage == PE_STAGE_NONE);
  REQUIRE(diag.offsetKnown == false);
  DestructParsedPE(good);
}

TEST_CASE("section failure reports the section stage and legacy code",
          "[diagnostic]") {
  auto path = fs::path(ASSETS_DIR) / "example.exe";
  auto bytes = readAll(path.string());

  // Locate the section table (immediately after the NT headers) and corrupt
  // the first section's raw-data range so section construction fails. The NT
  // headers are at e_lfanew; for a PE32+ image the section table follows the
  // optional header whose size is stored in the file header.
  std::uint32_t lfanew = 0;
  std::memcpy(&lfanew, bytes.data() + 0x3C, sizeof(lfanew));

  constexpr std::uint32_t kFileHeaderSizeOffset = 4 + 16; // after Signature
  std::uint16_t sizeOfOptionalHeader = 0;
  std::memcpy(&sizeOfOptionalHeader,
              bytes.data() + lfanew + kFileHeaderSizeOffset,
              sizeof(sizeOfOptionalHeader));

  const std::uint32_t sectionTable =
      lfanew + 4 + 20 + sizeOfOptionalHeader;
  constexpr std::uint32_t kSizeOfRawDataOffset = 16;

  // Point the raw range beyond the end of the file.
  std::uint32_t oversized =
      static_cast<std::uint32_t>(bytes.size()) + 0x1000;
  std::memcpy(bytes.data() + sectionTable + kSizeOfRawDataOffset,
              &oversized,
              sizeof(oversized));

  PEDiagnostic diag;
  parsed_pe *pe =
      ParsePEFromPointer(bytes.data(),
                         static_cast<std::uint32_t>(bytes.size()),
                         &diag);

  REQUIRE(pe == nullptr);
  REQUIRE(diag.stage == PE_STAGE_SECTIONS);
  REQUIRE(GetPEErr() == PEERR_SECT);
  REQUIRE_FALSE(diag.functionLocation.empty());
}

TEST_CASE("stage names are stable strings", "[diagnostic]") {
  REQUIRE(std::string(PEParseStageToString(PE_STAGE_NONE)) == "None");
  REQUIRE(std::string(PEParseStageToString(PE_STAGE_DOS_HEADER)) ==
          "DOSHeader");
  REQUIRE(std::string(PEParseStageToString(PE_STAGE_NT_HEADERS)) ==
          "NTHeaders");
  REQUIRE(std::string(PEParseStageToString(PE_STAGE_RESOURCES)) ==
          "Resources");
  REQUIRE(std::string(PEParseStageToString(PE_STAGE_IMPORTS)) == "Imports");
  REQUIRE(std::string(PEParseStageToString(
              static_cast<pe_parse_stage>(0xFFFF))) == "Unknown");
}

TEST_CASE("post-parse accessor errors do not touch the completed diagnostic",
          "[diagnostic]") {
  auto path = fs::path(ASSETS_DIR) / "example.exe";

  PEDiagnostic diag;
  parsed_pe *pe = ParsePEFromFile(path.string().c_str(), &diag);
  REQUIRE(pe != nullptr);
  REQUIRE(diag.code == PEERR_NONE);

  // A failing runtime accessor reports through the thread-local legacy
  // interface only; the completed parse's diagnostic stays clean.
  std::uint8_t byte = 0;
  bool ok = ReadByteAtVA(pe, static_cast<VA>(~0ULL), byte);
  REQUIRE_FALSE(ok);
  REQUIRE(GetPEErr() == PEERR_SECTVA);
  REQUIRE(diag.code == PEERR_NONE);

  DestructParsedPE(pe);
}

TEST_CASE("an out-of-section import records directory and offset",
          "[diagnostic]") {
  // Construct a minimal PE32 whose import directory names a module outside
  // of any section, forcing a section-lookup failure during the import
  // stage.
  constexpr std::uint32_t kNtHeaderOffset = 0x80;
  constexpr std::uint32_t kSectionRva = 0x1000;
  constexpr std::uint32_t kSectionRawOffset = 0x200;
  constexpr std::uint32_t kSectionRawSize = 0x200;
  constexpr std::size_t kFileSize = kSectionRawOffset + kSectionRawSize;
  std::array<std::uint8_t, kFileSize> pe{};

  auto put16 = [&](std::size_t offset, std::uint16_t value) {
    pe[offset] = static_cast<std::uint8_t>(value);
    pe[offset + 1] = static_cast<std::uint8_t>(value >> 8);
  };
  auto put32 = [&](std::size_t offset, std::uint32_t value) {
    pe[offset] = static_cast<std::uint8_t>(value);
    pe[offset + 1] = static_cast<std::uint8_t>(value >> 8);
    pe[offset + 2] = static_cast<std::uint8_t>(value >> 16);
    pe[offset + 3] = static_cast<std::uint8_t>(value >> 24);
  };

  put16(offsetof(dos_header, e_magic), MZ_MAGIC);
  put32(offsetof(dos_header, e_lfanew), kNtHeaderOffset);
  put32(kNtHeaderOffset, NT_MAGIC);

  const std::size_t fileHeaderOffset = kNtHeaderOffset + 4;
  put16(fileHeaderOffset + offsetof(file_header, Machine),
        IMAGE_FILE_MACHINE_I386);
  put16(fileHeaderOffset + offsetof(file_header, NumberOfSections), 1);
  put16(fileHeaderOffset + offsetof(file_header, SizeOfOptionalHeader),
        sizeof(optional_header_32));

  const std::size_t optionalHeaderOffset =
      fileHeaderOffset + sizeof(file_header);
  put16(optionalHeaderOffset + offsetof(optional_header_32, Magic),
        NT_OPTIONAL_32_MAGIC);
  put32(optionalHeaderOffset +
            offsetof(optional_header_32, NumberOfRvaAndSizes),
        NUM_DIR_ENTRIES);

  const std::size_t sectionHeaderOffset =
      optionalHeaderOffset + sizeof(optional_header_32);
  std::memcpy(pe.data() + sectionHeaderOffset, ".text\0\0\0", 8);
  put32(sectionHeaderOffset + offsetof(image_section_header, Misc.VirtualSize),
        kSectionRawSize);
  put32(sectionHeaderOffset +
            offsetof(image_section_header, VirtualAddress),
        kSectionRva);
  put32(sectionHeaderOffset +
            offsetof(image_section_header, SizeOfRawData),
        kSectionRawSize);
  put32(sectionHeaderOffset +
            offsetof(image_section_header, PointerToRawData),
        kSectionRawOffset);

  const std::size_t importDirectoryOffset =
      optionalHeaderOffset + offsetof(optional_header_32, DataDirectory) +
      (DIR_IMPORT * sizeof(data_directory));
  put32(importDirectoryOffset + offsetof(data_directory, VirtualAddress),
        kSectionRva);
  put32(importDirectoryOffset + offsetof(data_directory, Size),
        sizeof(import_dir_entry));

  // The import entry's NameRVA points beyond the section.
  put32(kSectionRawOffset + offsetof(import_dir_entry, NameRVA),
        kSectionRva + kSectionRawSize + 0x50);
  put32(kSectionRawOffset + offsetof(import_dir_entry, AddressRVA),
        kSectionRva + 8);

  PEDiagnostic diag;
  parsed_pe *parsed =
      ParsePEFromPointer(pe.data(),
                         static_cast<std::uint32_t>(pe.size()),
                         &diag);

  REQUIRE(parsed == nullptr);
  REQUIRE(diag.code == PEERR_SECTVA);
  REQUIRE(diag.stage == PE_STAGE_IMPORTS);
  REQUIRE(diag.directoryKnown);
  REQUIRE(diag.directory == DIR_IMPORT);
  REQUIRE(diag.offsetKnown);
  REQUIRE(GetPEErr() == PEERR_SECTVA);
}

} // namespace peparse
