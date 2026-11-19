#include <pe-parse/parse.h>

#include <array>
#include <catch2/catch.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>

#include "filesystem_compat.h"

namespace peparse {
namespace {

constexpr std::uint32_t kNtHeaderOffset = 0x80;
constexpr std::uint32_t kSectionRva = 0x2000;
constexpr std::uint32_t kSectionRawOffset = 0x200;
constexpr std::uint32_t kSectionRawSize = 0x1200;
constexpr std::uint32_t kLoadConfigRva = 0x2100;
constexpr std::uint32_t kTableRva = 0x2400;
constexpr std::uint32_t kImageBase = 0x400000;
constexpr std::size_t kFileSize = kSectionRawOffset + kSectionRawSize;

using TestPe = std::array<std::uint8_t, kFileSize>;
using ParsedPePtr = std::unique_ptr<parsed_pe, void (*)(parsed_pe *)>;

template <typename T>
void put16(T &buffer, std::size_t offset, std::uint16_t value) {
  buffer[offset] = static_cast<std::uint8_t>(value);
  buffer[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

template <typename T>
void put32(T &buffer, std::size_t offset, std::uint32_t value) {
  buffer[offset] = static_cast<std::uint8_t>(value);
  buffer[offset + 1] = static_cast<std::uint8_t>(value >> 8);
  buffer[offset + 2] = static_cast<std::uint8_t>(value >> 16);
  buffer[offset + 3] = static_cast<std::uint8_t>(value >> 24);
}

template <typename T>
void put64(T &buffer, std::size_t offset, std::uint64_t value) {
  for (std::size_t i = 0; i < sizeof(value); ++i) {
    buffer[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
  }
}

constexpr std::size_t optionalHeaderOffset() {
  return kNtHeaderOffset + sizeof(std::uint32_t) + sizeof(file_header);
}

constexpr std::size_t sectionHeaderOffset() {
  return optionalHeaderOffset() + sizeof(optional_header_32);
}

constexpr std::size_t dataDirectoryOffset(data_directory_kind kind) {
  return optionalHeaderOffset() + offsetof(optional_header_32, DataDirectory) +
         (static_cast<std::size_t>(kind) * sizeof(data_directory));
}

void putDataDirectory(TestPe &pe,
                      data_directory_kind kind,
                      std::uint32_t virtualAddress,
                      std::uint32_t size) {
  const auto offset = dataDirectoryOffset(kind);
  put32(pe, offset + offsetof(data_directory, VirtualAddress), virtualAddress);
  put32(pe, offset + offsetof(data_directory, Size), size);
}

void putDllCharacteristics(TestPe &pe, std::uint16_t characteristics) {
  put16(pe,
        optionalHeaderOffset() +
            offsetof(optional_header_32, DllCharacteristics),
        characteristics);
}

std::size_t sectionOffset(std::uint32_t rva) {
  return kSectionRawOffset + (rva - kSectionRva);
}

TestPe makeMinimalPe() {
  TestPe pe{};

  put16(pe, offsetof(dos_header, e_magic), MZ_MAGIC);
  put32(pe, offsetof(dos_header, e_lfanew), kNtHeaderOffset);
  put32(pe, kNtHeaderOffset, NT_MAGIC);

  constexpr auto kFileHeaderOffset =
      kNtHeaderOffset + offsetof(nt_header_32, FileHeader);
  put16(pe,
        kFileHeaderOffset + offsetof(file_header, Machine),
        IMAGE_FILE_MACHINE_I386);
  put16(pe, kFileHeaderOffset + offsetof(file_header, NumberOfSections), 1);

  put16(pe,
        optionalHeaderOffset() + offsetof(optional_header_32, Magic),
        NT_OPTIONAL_32_MAGIC);
  put32(pe,
        optionalHeaderOffset() +
            offsetof(optional_header_32, NumberOfRvaAndSizes),
        NUM_DIR_ENTRIES);
  put32(pe,
        optionalHeaderOffset() + offsetof(optional_header_32, ImageBase),
        kImageBase);

  constexpr auto kSectionHeaderOffset = sectionHeaderOffset();
  put32(pe,
        kSectionHeaderOffset + offsetof(image_section_header, Misc.VirtualSize),
        kSectionRawSize);
  put32(pe,
        kSectionHeaderOffset + offsetof(image_section_header, VirtualAddress),
        kSectionRva);
  put32(pe,
        kSectionHeaderOffset + offsetof(image_section_header, SizeOfRawData),
        kSectionRawSize);
  put32(pe,
        kSectionHeaderOffset + offsetof(image_section_header, PointerToRawData),
        kSectionRawOffset);

  return pe;
}

// Offsets into the 32-bit load configuration structure, mirroring what the
// Windows SDK defines for IMAGE_LOAD_CONFIG_DIRECTORY32.
constexpr std::uint32_t kLcSize = 0;
constexpr std::uint32_t kLcSecurityCookie = 60;
constexpr std::uint32_t kLcSEHandlerTable = 64;
constexpr std::uint32_t kLcSEHandlerCount = 68;
constexpr std::uint32_t kLcGuardCFFunctionTable = 80;
constexpr std::uint32_t kLcGuardCFFunctionCount = 84;
constexpr std::uint32_t kLcGuardFlags = 88;
constexpr std::uint32_t kFullLcSize = 92;

void putLoadConfigDword(TestPe &pe,
                        std::uint32_t fieldOffset,
                        std::uint32_t value) {
  put32(pe, sectionOffset(kLoadConfigRva) + fieldOffset, value);
}

void declareLoadConfig(TestPe &pe,
                       std::uint32_t structureSize,
                       std::uint32_t directorySize) {
  putDataDirectory(pe, DIR_LOAD_CONFIG, kLoadConfigRva, directorySize);
  putLoadConfigDword(pe, kLcSize, structureSize);
}

ParsedPePtr parse(TestPe &pe) {
  return ParsedPePtr(
      ParsePEFromPointer(pe.data(), static_cast<std::uint32_t>(pe.size())),
      DestructParsedPE);
}

// A minimal 64-bit image. The optional header layout differs from the 32-bit
// one, so the section table and data directories live at different offsets.
constexpr std::uint64_t kImageBase64 = 0x140000000ULL;

constexpr std::size_t optionalHeader64Offset() {
  return kNtHeaderOffset + sizeof(std::uint32_t) + sizeof(file_header);
}

constexpr std::size_t sectionHeader64Offset() {
  return optionalHeader64Offset() + sizeof(optional_header_64);
}

void putDataDirectory64(TestPe &pe,
                        data_directory_kind kind,
                        std::uint32_t virtualAddress,
                        std::uint32_t size) {
  const auto offset = optionalHeader64Offset() +
                      offsetof(optional_header_64, DataDirectory) +
                      (static_cast<std::size_t>(kind) * sizeof(data_directory));
  put32(pe, offset + offsetof(data_directory, VirtualAddress), virtualAddress);
  put32(pe, offset + offsetof(data_directory, Size), size);
}

TestPe makeMinimalPe64() {
  TestPe pe{};

  put16(pe, offsetof(dos_header, e_magic), MZ_MAGIC);
  put32(pe, offsetof(dos_header, e_lfanew), kNtHeaderOffset);
  put32(pe, kNtHeaderOffset, NT_MAGIC);

  constexpr auto kFileHeaderOffset =
      kNtHeaderOffset + offsetof(nt_header_32, FileHeader);
  put16(pe,
        kFileHeaderOffset + offsetof(file_header, Machine),
        IMAGE_FILE_MACHINE_AMD64);
  put16(pe, kFileHeaderOffset + offsetof(file_header, NumberOfSections), 1);

  put16(pe,
        optionalHeader64Offset() + offsetof(optional_header_64, Magic),
        NT_OPTIONAL_64_MAGIC);
  put32(pe,
        optionalHeader64Offset() +
            offsetof(optional_header_64, NumberOfRvaAndSizes),
        NUM_DIR_ENTRIES);
  put64(pe,
        optionalHeader64Offset() + offsetof(optional_header_64, ImageBase),
        kImageBase64);

  constexpr auto kSecHeader = sectionHeader64Offset();
  put32(pe,
        kSecHeader + offsetof(image_section_header, Misc.VirtualSize),
        kSectionRawSize);
  put32(pe,
        kSecHeader + offsetof(image_section_header, VirtualAddress),
        kSectionRva);
  put32(pe,
        kSecHeader + offsetof(image_section_header, SizeOfRawData),
        kSectionRawSize);
  put32(pe,
        kSecHeader + offsetof(image_section_header, PointerToRawData),
        kSectionRawOffset);

  return pe;
}

// Offsets into the 64-bit load configuration structure.
constexpr std::uint32_t kLc64GuardCFFunctionTable = 128;
constexpr std::uint32_t kLc64GuardCFFunctionCount = 136;
constexpr std::uint32_t kLc64GuardFlags = 144;
constexpr std::uint32_t kFullLc64Size = 148;

void putLoadConfigQword(TestPe &pe,
                        std::uint32_t fieldOffset,
                        std::uint64_t value) {
  put64(pe, sectionOffset(kLoadConfigRva) + fieldOffset, value);
}

} // namespace

TEST_CASE("absent load configuration is reported as absent", "[mitigation]") {
  auto pe = makeMinimalPe();
  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_ABSENT);
  REQUIRE_FALSE(metadata.isPresent);
  REQUIRE_FALSE(metadata.hasGuardFlags);
  REQUIRE_FALSE(metadata.hasGuardCFFunctionTable);
}

TEST_CASE("security features are read even when no load configuration exists",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  putDllCharacteristics(pe,
                        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                            IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
                            IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_ABSENT);
  REQUIRE(metadata.aslr);
  REQUIRE(metadata.dep);
  REQUIRE(metadata.highEntropyVA);
  REQUIRE_FALSE(metadata.controlFlowGuard);
}

TEST_CASE("complete load configuration is reported as consistent",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  declareLoadConfig(pe, kFullLcSize, kFullLcSize);
  putLoadConfigDword(pe, kLcSecurityCookie, kImageBase + 0x2800);
  putLoadConfigDword(pe, kLcGuardFlags, IMAGE_GUARD_CF_INSTRUMENTED);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_CONSISTENT);
  REQUIRE(metadata.isPresent);
  REQUIRE(metadata.declaredSize == kFullLcSize);
  REQUIRE(metadata.structureSize == kFullLcSize);
  REQUIRE(metadata.hasSecurityCookie);
  REQUIRE(metadata.securityCookie == kImageBase + 0x2800);
  REQUIRE(metadata.hasGuardFlags);
  REQUIRE(metadata.cfgInstrumented);
}

TEST_CASE("a shorter older structure leaves optional fields unavailable",
          "[mitigation]") {
  // 68 bytes covers Size..SEHandlerTable but not SEHandlerCount or any of the
  // Guard fields. The image is an older format, not corrupt.
  constexpr std::uint32_t kOldSize = 68;

  auto pe = makeMinimalPe();
  declareLoadConfig(pe, kOldSize, kOldSize);
  putLoadConfigDword(pe, kLcSecurityCookie, kImageBase + 0x2800);
  // Bytes beyond the declared structure must be ignored even though they lie
  // in the same section.
  putLoadConfigDword(pe, kLcGuardFlags, 0xffffffff);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_CONSISTENT);
  REQUIRE(metadata.hasSecurityCookie);
  REQUIRE_FALSE(metadata.hasGuardFlags);
  REQUIRE(metadata.guardFlags == 0);
  REQUIRE_FALSE(metadata.hasGuardCFFunctionTable);
}

TEST_CASE("directory size beyond the containing section is truncated",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  // The structure begins near the end of the section, so the declared
  // directory size cannot be satisfied by file-backed data.
  constexpr std::uint32_t kEndRva = kSectionRva + kSectionRawSize - 16;
  putDataDirectory(pe, DIR_LOAD_CONFIG, kEndRva, 0x100);
  put32(pe, sectionOffset(kEndRva) + kLcSize, 0x100);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_TRUNCATED);
  REQUIRE_FALSE(metadata.hasGuardFlags);
}

TEST_CASE("load configuration RVA outside any section is truncated",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  // Points past the single section; the bytes at this RVA do not exist.
  putDataDirectory(pe, DIR_LOAD_CONFIG, kSectionRva + kSectionRawSize, 0x40);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_TRUNCATED);
  REQUIRE_FALSE(metadata.hasSecurityCookie);
}

TEST_CASE("a structure size smaller than its own header is truncated",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  declareLoadConfig(pe, 2, 0x100);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_TRUNCATED);
}

TEST_CASE("a structure size larger than the directory is truncated",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  declareLoadConfig(pe, kFullLcSize, 32);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_TRUNCATED);
}

TEST_CASE("half-declared Guard table is inconsistent", "[mitigation]") {
  auto pe = makeMinimalPe();
  declareLoadConfig(pe, kFullLcSize, kFullLcSize);
  putLoadConfigDword(pe, kLcGuardFlags, IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT);
  // A table pointer with no count does not describe any table.
  putLoadConfigDword(pe, kLcGuardCFFunctionTable, kImageBase + kTableRva);
  putLoadConfigDword(pe, kLcGuardCFFunctionCount, 0);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_INCONSISTENT);
  REQUIRE(metadata.hasGuardCFFunctionTable);
  REQUIRE_FALSE(metadata.guardCFFunctionTableValid);
}

TEST_CASE("GuardFlags table-presence flag without a table is inconsistent",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  declareLoadConfig(pe, kFullLcSize, kFullLcSize);
  putLoadConfigDword(pe, kLcGuardFlags, IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_INCONSISTENT);
  REQUIRE(metadata.cfgFunctionTablePresent);
  REQUIRE_FALSE(metadata.guardCFFunctionTableValid);
}

TEST_CASE("a complete Guard function table is valid", "[mitigation]") {
  auto pe = makeMinimalPe();
  declareLoadConfig(pe, kFullLcSize, kFullLcSize);
  putLoadConfigDword(pe,
                     kLcGuardFlags,
                     IMAGE_GUARD_CF_INSTRUMENTED |
                         IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT);
  putLoadConfigDword(pe, kLcGuardCFFunctionTable, kImageBase + kTableRva);
  putLoadConfigDword(pe, kLcGuardCFFunctionCount, 16);
  // Populate the table so the file-backed bytes actually exist.
  for (std::uint32_t i = 0; i < 16; i++) {
    put32(pe, sectionOffset(kTableRva) + i * 4, kImageBase + 0x1000 + i);
  }

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_CONSISTENT);
  REQUIRE(metadata.hasGuardCFFunctionTable);
  REQUIRE(metadata.guardCFFunctionTableValid);
  REQUIRE(metadata.guardCFFunctionTableRVA == kTableRva);
  REQUIRE(metadata.guardCFFunctionCount == 16);
  REQUIRE(metadata.guardCFFunctionTableStride == 4);
}

TEST_CASE("a Guard function table that runs past the section is truncated",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  declareLoadConfig(pe, kFullLcSize, kFullLcSize);
  putLoadConfigDword(pe,
                     kLcGuardFlags,
                     IMAGE_GUARD_CF_INSTRUMENTED |
                         IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT);
  // Start the table close to the section end and claim more entries than the
  // remaining bytes can hold.
  constexpr std::uint32_t kNearEndRva = kSectionRva + kSectionRawSize - 8;
  putLoadConfigDword(pe, kLcGuardCFFunctionTable, kImageBase + kNearEndRva);
  putLoadConfigDword(pe, kLcGuardCFFunctionCount, 16);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_TRUNCATED);
  REQUIRE(metadata.hasGuardCFFunctionTable);
  REQUIRE_FALSE(metadata.guardCFFunctionTableValid);
}

TEST_CASE("a Guard function table pointer outside the image is truncated",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  declareLoadConfig(pe, kFullLcSize, kFullLcSize);
  putLoadConfigDword(pe,
                     kLcGuardFlags,
                     IMAGE_GUARD_CF_INSTRUMENTED |
                         IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT);
  // Below the image base, so no RVA can be derived.
  putLoadConfigDword(pe, kLcGuardCFFunctionTable, 0x1000);
  putLoadConfigDword(pe, kLcGuardCFFunctionCount, 4);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_TRUNCATED);
  REQUIRE_FALSE(metadata.guardCFFunctionTableValid);
}

TEST_CASE("the Guard function table stride comes from GuardFlags",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  declareLoadConfig(pe, kFullLcSize, kFullLcSize);
  // Stride extra of 4 bytes (mask field set to 4 << 28).
  const std::uint32_t extra = 4u << IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;
  putLoadConfigDword(pe,
                     kLcGuardFlags,
                     IMAGE_GUARD_CF_INSTRUMENTED |
                         IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT | extra);
  putLoadConfigDword(pe, kLcGuardCFFunctionTable, kImageBase + kTableRva);
  // With a stride of 8, 8 entries need 64 bytes. Claim 32 entries: 256 bytes
  // also fit, so the table stays valid; but the stride must be reported.
  putLoadConfigDword(pe, kLcGuardCFFunctionCount, 8);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.guardCFFunctionTableStride == 8);
  REQUIRE(metadata.status == MITIGATION_CONSISTENT);
  REQUIRE(metadata.guardCFFunctionTableValid);
}

TEST_CASE("DllCharacteristics claiming CFG without instrumentation is "
          "inconsistent",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  putDllCharacteristics(pe, IMAGE_DLLCHARACTERISTICS_GUARD_CF);
  declareLoadConfig(pe, kFullLcSize, kFullLcSize);
  // GuardFlags is present but describes no instrumentation.
  putLoadConfigDword(pe, kLcGuardFlags, 0);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.controlFlowGuard);
  REQUIRE(metadata.status == MITIGATION_INCONSISTENT);
}

TEST_CASE("DllCharacteristics claiming CFG without GuardFlags stays consistent",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  putDllCharacteristics(pe, IMAGE_DLLCHARACTERISTICS_GUARD_CF);
  // An older structure that ends before GuardFlags: the feature cannot be
  // verified, so it is not treated as a conflict.
  declareLoadConfig(pe, 68, 68);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_CONSISTENT);
  REQUIRE_FALSE(metadata.hasGuardFlags);
}

TEST_CASE("a security cookie declared unused but present is inconsistent",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  declareLoadConfig(pe, kFullLcSize, kFullLcSize);
  putLoadConfigDword(pe, kLcSecurityCookie, kImageBase + 0x2800);
  putLoadConfigDword(pe, kLcGuardFlags, IMAGE_GUARD_SECURITY_COOKIE_UNUSED);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.securityCookieUnused);
  REQUIRE(metadata.status == MITIGATION_INCONSISTENT);
}

TEST_CASE("probing mitigation metadata leaves the parser error state intact",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  declareLoadConfig(pe, kFullLcSize, kFullLcSize);
  putLoadConfigDword(pe, kLcGuardFlags, IMAGE_GUARD_CF_INSTRUMENTED);

  auto p = parse(pe);
  REQUIRE(p);

  // A truncated directory makes the probe read out of bounds internally; that
  // must not leak into the caller-visible error state. The legacy error state
  // is process-global and sticky, so compare against whatever value is
  // visible before the query rather than assuming it is clean.
  auto truncated = makeMinimalPe();
  putDataDirectory(
      truncated, DIR_LOAD_CONFIG, kSectionRva + kSectionRawSize, 8);
  auto p2 = parse(truncated);
  REQUIRE(p2);

  const std::uint32_t errBefore = GetPEErr();
  const std::string errLocBefore = GetPEErrLoc();

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p2.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_TRUNCATED);
  REQUIRE(GetPEErr() == errBefore);
  REQUIRE(GetPEErrLoc() == errLocBefore);
}

TEST_CASE("a Guard table that would need bytes past the directory end is still "
          "bounded by the section",
          "[mitigation]") {
  // The data directory Size is only a hint for the load configuration itself;
  // the referenced tables live in arbitrary sections. Confirm that table
  // validation is against the section's file-backed bytes, and that trailing
  // bytes inside the section are only counted as table entries when the
  // declared count reaches them.
  auto pe = makeMinimalPe();
  declareLoadConfig(pe, kFullLcSize, kFullLcSize);
  putLoadConfigDword(pe,
                     kLcGuardFlags,
                     IMAGE_GUARD_CF_INSTRUMENTED |
                         IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT);
  // One entry, entirely inside the section: valid even though only that byte
  // range is covered.
  putLoadConfigDword(pe, kLcGuardCFFunctionTable, kImageBase + kTableRva);
  putLoadConfigDword(pe, kLcGuardCFFunctionCount, 1);
  put32(pe, sectionOffset(kTableRva), kImageBase + 0x1000);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_CONSISTENT);
  REQUIRE(metadata.guardCFFunctionTableValid);
  REQUIRE(metadata.guardCFFunctionCount == 1);
}

TEST_CASE("an overflow-sized Guard table count is truncated", "[mitigation]") {
  auto pe = makeMinimalPe();
  declareLoadConfig(pe, kFullLcSize, kFullLcSize);
  putLoadConfigDword(pe,
                     kLcGuardFlags,
                     IMAGE_GUARD_CF_INSTRUMENTED |
                         IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT);
  putLoadConfigDword(pe, kLcGuardCFFunctionTable, kImageBase + kTableRva);
  putLoadConfigDword(pe, kLcGuardCFFunctionCount, 0xffffffffu);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_TRUNCATED);
  REQUIRE_FALSE(metadata.guardCFFunctionTableValid);
}

TEST_CASE("a real 64-bit image reports its mitigation metadata",
          "[mitigation][assets]") {
  const fs::path path = fs::path(ASSETS_DIR) / "example.exe";
  ParsedPePtr p(ParsePEFromFile(path.string().c_str()), DestructParsedPE);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));

  // example.exe is PE32+, declares a 0x100-byte load configuration at a
  // section-backed RVA, and sets CFG instrumentation flags.
  REQUIRE(metadata.isPresent);
  REQUIRE(metadata.status == MITIGATION_CONSISTENT);
  REQUIRE(metadata.structureSize == 0x100);
  REQUIRE(metadata.aslr);
  REQUIRE(metadata.dep);
  REQUIRE(metadata.hasSecurityCookie);
  REQUIRE(metadata.securityCookie == 0x14001c038);
  REQUIRE(metadata.hasGuardFlags);
  REQUIRE(metadata.cfgInstrumented);
  REQUIRE_FALSE(metadata.controlFlowGuard);
  // No function table is declared, and an absent table is not an error.
  REQUIRE(metadata.hasGuardCFFunctionTable);
  REQUIRE(metadata.guardCFFunctionCount == 0);
}

TEST_CASE("a flagged table whose fields the structure omits is truncated",
          "[mitigation]") {
  // A 92-byte structure reaches GuardFlags (offset 88) but stops before the
  // address-taken IAT and long jump table fields at offsets 104 and 112.
  constexpr std::uint32_t kSizeToGuardFlags = 92;

  auto pe = makeMinimalPe();
  declareLoadConfig(pe, kSizeToGuardFlags, kSizeToGuardFlags);
  putLoadConfigDword(pe, kLcGuardFlags, IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.hasGuardFlags);
  REQUIRE(metadata.cfgLongJumpTablePresent);
  REQUIRE_FALSE(metadata.hasGuardLongJumpTargetTable);
  REQUIRE(metadata.status == MITIGATION_TRUNCATED);
}

TEST_CASE("a 64-bit load configuration resolves its Guard table",
          "[mitigation]") {
  auto pe = makeMinimalPe64();
  putDataDirectory64(pe, DIR_LOAD_CONFIG, kLoadConfigRva, kFullLc64Size);
  putLoadConfigDword(pe, kLcSize, kFullLc64Size);
  putLoadConfigDword(pe,
                     kLc64GuardFlags,
                     IMAGE_GUARD_CF_INSTRUMENTED |
                         IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT);
  putLoadConfigQword(pe, kLc64GuardCFFunctionTable, kImageBase64 + kTableRva);
  putLoadConfigQword(pe, kLc64GuardCFFunctionCount, 4);
  for (std::uint32_t i = 0; i < 4; i++) {
    put32(pe,
          sectionOffset(kTableRva) + i * 4,
          static_cast<std::uint32_t>(kImageBase64 + 0x1000 + i));
  }

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.status == MITIGATION_CONSISTENT);
  REQUIRE(metadata.hasGuardCFFunctionTable);
  REQUIRE(metadata.guardCFFunctionTableValid);
  REQUIRE(metadata.guardCFFunctionTableRVA == kTableRva);
  REQUIRE(metadata.guardCFFunctionCount == 4);
}

TEST_CASE("a declared SEH table contradicts IMAGE_DLLCHARACTERISTICS_NO_SEH",
          "[mitigation]") {
  auto pe = makeMinimalPe();
  putDllCharacteristics(pe, IMAGE_DLLCHARACTERISTICS_NO_SEH);
  // A structure that covers SecurityCookie and the SEH fields (through 72).
  constexpr std::uint32_t kSizeThroughSEH = 72;
  declareLoadConfig(pe, kSizeThroughSEH, kSizeThroughSEH);
  putLoadConfigDword(pe, kLcSEHandlerTable, kImageBase + kTableRva);
  putLoadConfigDword(pe, kLcSEHandlerCount, 2);

  auto p = parse(pe);
  REQUIRE(p);

  mitigation_metadata metadata;
  REQUIRE(GetMitigationMetadata(p.get(), metadata));
  REQUIRE(metadata.noSEH);
  REQUIRE(metadata.hasSEHandlerTable);
  REQUIRE_FALSE(metadata.seHandlerTableValid);
  REQUIRE(metadata.status == MITIGATION_INCONSISTENT);
}

TEST_CASE("mitigation status has a stable string form", "[mitigation]") {
  REQUIRE(std::string(GetMitigationStatusAsString(MITIGATION_ABSENT)) ==
          "absent");
  REQUIRE(std::string(GetMitigationStatusAsString(MITIGATION_TRUNCATED)) ==
          "truncated");
  REQUIRE(std::string(GetMitigationStatusAsString(MITIGATION_INCONSISTENT)) ==
          "inconsistent");
  REQUIRE(std::string(GetMitigationStatusAsString(MITIGATION_CONSISTENT)) ==
          "consistent");
}

TEST_CASE("a null parsed PE has no mitigation metadata", "[mitigation]") {
  mitigation_metadata metadata;
  REQUIRE_FALSE(GetMitigationMetadata(nullptr, metadata));
}

} // namespace peparse
