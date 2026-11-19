#include <pe-parse/parse.h>

#include <array>
#include <catch2/catch.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "filesystem_compat.h"

namespace peparse {
namespace {

// The NT header is placed well past the DOS stub so tests can relocate it
// earlier without the two copies overlapping.
constexpr std::uint32_t kNtHeaderOffset = 0x200;
constexpr std::uint32_t kRichStartOffset = 0x80;
constexpr std::uint32_t kSectionRva = 0x2000;
constexpr std::uint32_t kSectionRawOffset = 0x400;
constexpr std::uint32_t kSectionRawSize = 0x200;
constexpr std::size_t kFileSize = kSectionRawOffset + kSectionRawSize;

// The fields of a Rich header entry, kept in the order they appear on disk.
struct RichEntrySpec {
  std::uint16_t productId;
  std::uint16_t buildNumber;
  std::uint32_t count;
};

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

std::uint32_t rol(std::uint32_t value, std::uint32_t bits) {
  bits &= 0x1F;
  return (value << bits) | (value >> ((32 - bits) & 0x1F));
}

constexpr std::size_t optionalHeaderOffset() {
  return kNtHeaderOffset + sizeof(std::uint32_t) + sizeof(file_header);
}

constexpr std::size_t sectionHeaderOffset() {
  return optionalHeaderOffset() + sizeof(optional_header_32);
}

// Relocate the NT headers (signature, file header, optional header and the
// single section header) so that the DOS stub can be made longer or shorter.
void moveNtHeader(TestPe &pe, std::uint32_t newLfanew) {
  put32(pe, offsetof(dos_header, e_lfanew), newLfanew);
  put32(pe, newLfanew, NT_MAGIC);

  const std::size_t fileHeaderOffset =
      newLfanew + offsetof(nt_header_32, FileHeader);
  put16(pe,
        fileHeaderOffset + offsetof(file_header, Machine),
        IMAGE_FILE_MACHINE_I386);
  put16(pe, fileHeaderOffset + offsetof(file_header, NumberOfSections), 1);

  const std::size_t optionalOffset =
      newLfanew + sizeof(std::uint32_t) + sizeof(file_header);
  put16(pe,
        optionalOffset + offsetof(optional_header_32, Magic),
        NT_OPTIONAL_32_MAGIC);
  put32(pe,
        optionalOffset + offsetof(optional_header_32, NumberOfRvaAndSizes),
        NUM_DIR_ENTRIES);

  const std::size_t sectionOffset = optionalOffset + sizeof(optional_header_32);
  put32(pe,
        sectionOffset + offsetof(image_section_header, Misc.VirtualSize),
        kSectionRawSize);
  put32(pe,
        sectionOffset + offsetof(image_section_header, VirtualAddress),
        kSectionRva);
  put32(pe,
        sectionOffset + offsetof(image_section_header, SizeOfRawData),
        kSectionRawSize);
  put32(pe,
        sectionOffset + offsetof(image_section_header, PointerToRawData),
        kSectionRawOffset);
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

// Compute the Rich checksum the way a linker would, so tests can build
// headers that validate without hard-coded magic numbers.
std::uint32_t computeChecksum(const TestPe &pe,
                              std::uint32_t startOffset,
                              const std::vector<RichEntrySpec> &entries) {
  std::uint32_t checksum = 0;

  for (std::uint32_t i = 0; i < startOffset; i++) {
    if (i >= 0x3C && i <= 0x3F) {
      continue;
    }
    checksum += rol(pe[i], i & 0x1F);
  }

  for (const RichEntrySpec &entry : entries) {
    const std::uint32_t compId =
        (static_cast<std::uint32_t>(entry.productId) << 16) |
        static_cast<std::uint32_t>(entry.buildNumber);
    checksum += rol(compId, entry.count & 0x1F);
  }

  checksum += startOffset;
  return checksum;
}

// Write a well-formed Rich header at `startOffset`, encrypted with `key`.
// Returns the offset just past the trailing key DWORD.
std::uint32_t putRichHeader(TestPe &pe,
                            std::uint32_t startOffset,
                            std::uint32_t key,
                            const std::vector<RichEntrySpec> &entries) {
  std::size_t offset = startOffset;
  put32(pe, offset, RICH_MAGIC_START ^ key);
  offset += 4;
  for (int i = 0; i < 3; i++) {
    put32(pe, offset, key);
    offset += 4;
  }

  for (const RichEntrySpec &entry : entries) {
    const std::uint32_t compId =
        (static_cast<std::uint32_t>(entry.productId) << 16) |
        static_cast<std::uint32_t>(entry.buildNumber);
    put32(pe, offset, compId ^ key);
    offset += 4;
    put32(pe, offset, entry.count ^ key);
    offset += 4;
  }

  put32(pe, offset, RICH_MAGIC_END);
  offset += 4;
  put32(pe, offset, key);
  offset += 4;

  return static_cast<std::uint32_t>(offset);
}

std::uint32_t putRichHeaderAtDefaultOffset(
    TestPe &pe, std::uint32_t key, const std::vector<RichEntrySpec> &entries) {
  return putRichHeader(pe, kRichStartOffset, key, entries);
}

ParsedPePtr parse(TestPe &pe) {
  return ParsedPePtr(
      ParsePEFromPointer(pe.data(), static_cast<std::uint32_t>(pe.size())),
      DestructParsedPE);
}

int captureRichEntry(void *ctx, const rich_entry &entry) {
  auto *entries = static_cast<std::vector<rich_entry> *>(ctx);
  entries->push_back(entry);
  return 0;
}

std::vector<rich_entry> readEntries(parsed_pe *pe) {
  std::vector<rich_entry> entries;
  IterRich(pe, captureRichEntry, &entries);
  return entries;
}

} // namespace

TEST_CASE("a consistent Rich header is reported as a valid fingerprint",
          "[rich]") {
  auto pe = makeMinimalPe();

  const std::vector<RichEntrySpec> entries{
      {0x0104, 0x6665, 3},
      {0x0103, 0x6665, 1},
      // Same product/build as the first entry: duplicates must be preserved
      // and must not disturb the walk.
      {0x0104, 0x6665, 3},
      // Zero count is legal and must not terminate the entry walk.
      {0x0105, 0x6852, 0},
  };

  const std::uint32_t key = 0x12345678;
  putRichHeaderAtDefaultOffset(pe, key, entries);

  // Derive the checksum the linker would have used: the XOR key is the
  // checksum of the DOS stub area and the entries. Re-emit the header with
  // that value so it validates.
  const std::uint32_t expectedKey =
      computeChecksum(pe, kRichStartOffset, entries);
  putRichHeaderAtDefaultOffset(pe, expectedKey, entries);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  REQUIRE(GetRichHeaderStatus(p.get()) == RICH_STATUS_VALID);
  REQUIRE(p->peHeader.rich.isPresent);
  REQUIRE(p->peHeader.rich.isValid);
  REQUIRE(p->peHeader.rich.DecryptionKey == expectedKey);
  REQUIRE(p->peHeader.rich.Checksum == expectedKey);
  REQUIRE(p->peHeader.rich.StartOffset == kRichStartOffset);
  REQUIRE(GetRichHeaderStatusString(RICH_STATUS_VALID) == std::string("valid"));

  const std::vector<rich_entry> parsed = readEntries(p.get());
  REQUIRE(parsed.size() == entries.size());
  for (std::size_t i = 0; i < entries.size(); i++) {
    REQUIRE(parsed[i].ProductId == entries[i].productId);
    REQUIRE(parsed[i].BuildNumber == entries[i].buildNumber);
    REQUIRE(parsed[i].Count == entries[i].count);
  }
}

TEST_CASE("a PE without a Rich header reports absent and still parses",
          "[rich]") {
  auto pe = makeMinimalPe();

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);
  REQUIRE(GetRichHeaderStatus(p.get()) == RICH_STATUS_ABSENT);
  REQUIRE_FALSE(p->peHeader.rich.isPresent);
  REQUIRE_FALSE(p->peHeader.rich.isValid);
  REQUIRE(readEntries(p.get()).empty());
  REQUIRE(GetRichHeaderStatusString(RICH_STATUS_ABSENT) ==
          std::string("absent"));
}

TEST_CASE("a header whose checksum does not match is reported as tampered",
          "[rich]") {
  auto pe = makeMinimalPe();

  const std::vector<RichEntrySpec> entries{{0x0104, 0x6665, 3}};
  const std::uint32_t realKey = computeChecksum(pe, kRichStartOffset, entries);

  // Encrypt with a different key than the checksum the DOS stub produces.
  putRichHeaderAtDefaultOffset(pe, realKey ^ 0x1, entries);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  REQUIRE(GetRichHeaderStatus(p.get()) == RICH_STATUS_CHECKSUM_MISMATCH);
  REQUIRE(p->peHeader.rich.isPresent);
  REQUIRE_FALSE(p->peHeader.rich.isValid);
  REQUIRE(p->peHeader.rich.Checksum != p->peHeader.rich.DecryptionKey);

  // Entries are still exposed for analysis even though the header is not
  // trustworthy.
  REQUIRE(readEntries(p.get()).size() == entries.size());
}

TEST_CASE("a header cut off before the Rich marker is reported as truncated",
          "[rich]") {
  auto pe = makeMinimalPe();

  const std::vector<RichEntrySpec> entries{{0x0104, 0x6665, 3}};
  const std::uint32_t key = computeChecksum(pe, kRichStartOffset, entries);
  putRichHeaderAtDefaultOffset(pe, key, entries);

  // Move the PE header so that the entries and the trailing "Rich" marker
  // fall outside the DOS stub. Only the prefix remains visible.
  constexpr std::uint32_t kTruncatedLfanew = kRichStartOffset + 16;
  moveNtHeader(pe, kTruncatedLfanew);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  REQUIRE(GetRichHeaderStatus(p.get()) == RICH_STATUS_TRUNCATED);
  REQUIRE(p->peHeader.rich.isPresent);
  REQUIRE_FALSE(p->peHeader.rich.isValid);
  REQUIRE(p->peHeader.rich.StartOffset == kRichStartOffset);
  REQUIRE(readEntries(p.get()).empty());
}

TEST_CASE("a header cut off inside the prefix is reported as truncated",
          "[rich]") {
  auto pe = makeMinimalPe();

  // Put only the "DanS" marker and two key copies in the stub area, with the
  // NT header starting immediately after them. The boundary is therefore
  // 12 bytes past the marker: enough evidence to know a Rich header started,
  // but not a complete prefix.
  constexpr std::uint32_t kPartialStart = 0x88;
  constexpr std::uint32_t kPartialLfanew = kPartialStart + 12;
  const std::uint32_t key = 0x11223344;
  put32(pe, kPartialStart, RICH_MAGIC_START ^ key);
  put32(pe, kPartialStart + 4, key);
  put32(pe, kPartialStart + 8, key);

  moveNtHeader(pe, kPartialLfanew);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  REQUIRE(GetRichHeaderStatus(p.get()) == RICH_STATUS_TRUNCATED);
  REQUIRE(p->peHeader.rich.isPresent);
  REQUIRE_FALSE(p->peHeader.rich.isValid);
  REQUIRE(p->peHeader.rich.StartOffset == kPartialStart);
  REQUIRE(readEntries(p.get()).empty());
}

TEST_CASE("an entry area that is not whole entries is an anomaly", "[rich]") {
  auto pe = makeMinimalPe();

  const std::vector<RichEntrySpec> entries{{0x0104, 0x6665, 3}};
  const std::uint32_t key = computeChecksum(pe, kRichStartOffset, entries);
  putRichHeaderAtDefaultOffset(pe, key, entries);

  // The header above has one entry: entry area 0x90..0x98, marker at 0x98.
  // Shift the marker out by one DWORD so the entry area is 12 bytes: one
  // whole entry plus a partial one.
  constexpr std::uint32_t kMarkerOffset = kRichStartOffset + 16 + 8;
  put32(pe, kMarkerOffset, 0xAABBCCDD);
  put32(pe, kMarkerOffset + 4, RICH_MAGIC_END);
  put32(pe, kMarkerOffset + 8, key);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  REQUIRE(GetRichHeaderStatus(p.get()) == RICH_STATUS_ENTRY_LENGTH_ANOMALY);
  REQUIRE(p->peHeader.rich.isPresent);
  REQUIRE_FALSE(p->peHeader.rich.isValid);
  // Only whole entries are surfaced; the trailing partial record is ignored.
  REQUIRE(readEntries(p.get()).size() == entries.size());
}

TEST_CASE("incidental DanS-like bytes in the DOS stub are not a fingerprint",
          "[rich]") {
  auto pe = makeMinimalPe();

  // Place a lone DWORD that decrypts to "DanS" under a key whose sibling
  // padding DWORDs do not match: the classic false positive.
  const std::uint32_t fakeKey = 0xDEADBEEF;
  put32(pe, 0x60, RICH_MAGIC_START ^ fakeKey);
  put32(pe, 0x64, 0x00000000);
  put32(pe, 0x68, 0x00000000);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);
  REQUIRE(GetRichHeaderStatus(p.get()) == RICH_STATUS_ABSENT);
  REQUIRE_FALSE(p->peHeader.rich.isPresent);
}

TEST_CASE("a lone Rich marker in the DOS stub is not a fingerprint", "[rich]") {
  auto pe = makeMinimalPe();

  // A "Rich" DWORD with no matching "DanS" prefix must not be treated as the
  // end of a structure.
  put32(pe, 0x70, RICH_MAGIC_END);
  put32(pe, 0x74, 0x11223344);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);
  REQUIRE(GetRichHeaderStatus(p.get()) == RICH_STATUS_ABSENT);
  REQUIRE_FALSE(p->peHeader.rich.isPresent);
}

TEST_CASE("a Rich header is found at a non-default offset", "[rich]") {
  auto pe = makeMinimalPe();

  // Move the PE header further out so the Rich header sits at 0xA0.
  constexpr std::uint32_t kNewLfanew = 0xC0;
  constexpr std::uint32_t kNewRichOffset = 0xA0;
  moveNtHeader(pe, kNewLfanew);

  const std::vector<RichEntrySpec> entries{{0x0104, 0x6665, 3}};
  const std::uint32_t key = computeChecksum(pe, kNewRichOffset, entries);
  putRichHeader(pe, kNewRichOffset, key, entries);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  REQUIRE(GetRichHeaderStatus(p.get()) == RICH_STATUS_VALID);
  REQUIRE(p->peHeader.rich.StartOffset == kNewRichOffset);
  REQUIRE(readEntries(p.get()).size() == entries.size());
}

TEST_CASE("a header with zero entries can still validate", "[rich]") {
  auto pe = makeMinimalPe();

  const std::vector<RichEntrySpec> entries;
  const std::uint32_t key = computeChecksum(pe, kRichStartOffset, entries);
  putRichHeaderAtDefaultOffset(pe, key, entries);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  REQUIRE(GetRichHeaderStatus(p.get()) == RICH_STATUS_VALID);
  REQUIRE(readEntries(p.get()).empty());
}

TEST_CASE("a prefix with a mismatched trailer key is a checksum mismatch",
          "[rich]") {
  auto pe = makeMinimalPe();

  const std::vector<RichEntrySpec> entries{{0x0104, 0x6665, 3}};
  const std::uint32_t key = computeChecksum(pe, kRichStartOffset, entries);
  const std::uint32_t headerEnd =
      putRichHeaderAtDefaultOffset(pe, key, entries);

  // Corrupt only the key stored after the trailing "Rich" marker.
  put32(pe, headerEnd - 4, key ^ 0xFF);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  REQUIRE(GetRichHeaderStatus(p.get()) == RICH_STATUS_CHECKSUM_MISMATCH);
  REQUIRE(p->peHeader.rich.isPresent);
  REQUIRE_FALSE(p->peHeader.rich.isValid);
}

TEST_CASE("a complete prefix is preferred over an earlier partial one",
          "[rich]") {
  auto pe = makeMinimalPe();

  // A decoy that has the "DanS" relation and two matching key copies, but no
  // third copy and no entries.
  const std::uint32_t decoyKey = 0xCAFEBABE;
  constexpr std::uint32_t kDecoyOffset = 0x60;
  put32(pe, kDecoyOffset, RICH_MAGIC_START ^ decoyKey);
  put32(pe, kDecoyOffset + 4, decoyKey);
  put32(pe, kDecoyOffset + 8, decoyKey);
  // A non-matching DWORD where the third key copy would be.
  put32(pe, kDecoyOffset + 12, 0xDEADBEEF);

  const std::vector<RichEntrySpec> entries{{0x0104, 0x6665, 3}};
  const std::uint32_t key = computeChecksum(pe, kRichStartOffset, entries);
  putRichHeaderAtDefaultOffset(pe, key, entries);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  // The real header at 0x80 must win over the partial decoy at 0x60.
  REQUIRE(GetRichHeaderStatus(p.get()) == RICH_STATUS_VALID);
  REQUIRE(p->peHeader.rich.StartOffset == kRichStartOffset);
  REQUIRE(readEntries(p.get()).size() == entries.size());
}

TEST_CASE("the real example executable has a valid Rich fingerprint",
          "[rich]") {
  fs::path path = fs::path(ASSETS_DIR) / "example.exe";
  ParsedPePtr p(ParsePEFromFile(path.string().c_str()), DestructParsedPE);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  REQUIRE(GetRichHeaderStatus(p.get()) == RICH_STATUS_VALID);
  REQUIRE(p->peHeader.rich.isPresent);
  REQUIRE(p->peHeader.rich.isValid);
  REQUIRE(p->peHeader.rich.DecryptionKey == 0x583c30ab);
  REQUIRE(p->peHeader.rich.Checksum == p->peHeader.rich.DecryptionKey);
  REQUIRE(readEntries(p.get()).size() == 10);
}

TEST_CASE("a null PE has no Rich status", "[rich]") {
  REQUIRE(GetRichHeaderStatus(nullptr) == RICH_STATUS_ABSENT);
}

} // namespace peparse
