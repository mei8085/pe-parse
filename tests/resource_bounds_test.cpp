#include <pe-parse/parse.h>

#include <array>
#include <catch2/catch.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace peparse {
namespace {

constexpr std::uint32_t kNtHeaderOffset = 0x80;
constexpr std::uint32_t kSectionRva = 0x2000;
constexpr std::uint32_t kSectionRawOffset = 0x200;
constexpr std::uint32_t kSectionRawSize = 0x1200;
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

constexpr std::size_t optionalHeaderOffset() {
  return kNtHeaderOffset + sizeof(std::uint32_t) + sizeof(file_header);
}

constexpr std::size_t sectionHeaderOffset() {
  return optionalHeaderOffset() + sizeof(optional_header_32);
}

TestPe makeResourcePe() {
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
  const char kName[] = ".rsrc";
  for (std::size_t i = 0; i < sizeof(kName); i++) {
    pe[kSectionHeaderOffset + offsetof(image_section_header, Name) + i] =
        static_cast<std::uint8_t>(kName[i]);
  }
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

// All offsets below are relative to the start of the .rsrc section, which
// is how the resource directory RVAs are interpreted by the parser.

void putTable(TestPe &pe,
              std::uint32_t offset,
              std::uint16_t nameEntries,
              std::uint16_t idEntries) {
  const auto o = kSectionRawOffset + offset;
  put16(pe, o + offsetof(resource_dir_table, NameEntries), nameEntries);
  put16(pe, o + offsetof(resource_dir_table, IDEntries), idEntries);
}

void putEntry(TestPe &pe,
              std::uint32_t offset,
              std::uint32_t id,
              std::uint32_t rva) {
  const auto o = kSectionRawOffset + offset;
  put32(pe, o, id);
  put32(pe, o + 4, rva);
}

void putDataEntry(TestPe &pe,
                  std::uint32_t offset,
                  std::uint32_t rva,
                  std::uint32_t size) {
  const auto o = kSectionRawOffset + offset;
  put32(pe, o + offsetof(resource_dat_entry, RVA), rva);
  put32(pe, o + offsetof(resource_dat_entry, size), size);
  put32(pe, o + offsetof(resource_dat_entry, codepage), 1252);
}

void putString(TestPe &pe, std::uint32_t offset, const char *value) {
  const auto o = kSectionRawOffset + offset;
  const auto len = static_cast<std::uint16_t>(std::strlen(value));
  put16(pe, o, len);
  for (std::uint16_t i = 0; i < len; i++) {
    put16(pe, o + 2 + i * 2, static_cast<std::uint8_t>(value[i]));
  }
}

void putData(TestPe &pe, std::uint32_t offset, const char *value) {
  auto o = kSectionRawOffset + offset;
  while (*value != '\0') {
    pe[o++] = static_cast<std::uint8_t>(*value++);
  }
}

ParsedPePtr parse(TestPe &pe) {
  return ParsedPePtr(
      ParsePEFromPointer(pe.data(), static_cast<std::uint32_t>(pe.size())),
      DestructParsedPE);
}

int captureResource(void *ctx, const resource &r) {
  auto *resources = static_cast<std::vector<resource> *>(ctx);
  resources->push_back(r);
  return 0;
}

std::vector<resource> collectResources(parsed_pe *pe) {
  std::vector<resource> resources;
  IterRsrc(pe, captureResource, &resources);
  return resources;
}

// Restores the process-wide resource parse limits when the test ends.
struct LimitsGuard {
  LimitsGuard() : saved(GetResourceParseLimits()) {
  }
  ~LimitsGuard() {
    SetResourceParseLimits(saved);
  }
  resource_parse_limits saved;
};

// A regular three-level tree with named type and name entries and two
// language data entries sharing the same payload.
TestPe makeNormalTreePe() {
  auto pe = makeResourcePe();

  putTable(pe, 0x00, 1, 0);
  putEntry(pe, 0x10, 0x80000100, 0x80000018); // type "MYTYPE" -> table @ 0x18

  putTable(pe, 0x18, 1, 0);
  putEntry(pe, 0x28, 0x80000110, 0x80000030); // name "MYNAME" -> table @ 0x30

  putTable(pe, 0x30, 0, 2);
  putEntry(pe, 0x40, 0x409, 0x180); // lang en-US -> data entry @ 0x180
  putEntry(pe, 0x48, 0x411, 0x190); // lang ja-JP -> data entry @ 0x190

  putDataEntry(pe, 0x180, kSectionRva + 0x1c0, 4);
  putDataEntry(pe, 0x190, kSectionRva + 0x1c0, 4);

  putString(pe, 0x100, "MYTYPE");
  putString(pe, 0x110, "MYNAME");
  putData(pe, 0x1c0, "ABCD");

  return pe;
}

} // namespace

TEST_CASE("normal resource trees keep names, hierarchy and data",
          "[resource]") {
  auto pe = makeNormalTreePe();
  auto parsed = parse(pe);
  REQUIRE(parsed != nullptr);

  auto resources = collectResources(parsed.get());
  REQUIRE(resources.size() == 2);

  for (const auto &r : resources) {
    REQUIRE(r.type_str == "MYTYPE");
    REQUIRE(r.name_str == "MYNAME");
    REQUIRE(r.type == 0x80000100);
    REQUIRE(r.name == 0x80000110);
    REQUIRE(r.size == 4);
    REQUIRE(r.buf != nullptr);
    REQUIRE(r.buf->bufLen == 4);
    REQUIRE(std::memcmp(r.buf->buf, "ABCD", 4) == 0);
  }
  REQUIRE(resources[0].lang == 0x409);
  REQUIRE(resources[1].lang == 0x411);
}

TEST_CASE("resource directory cycles are rejected with a stable error",
          "[resource]") {
  auto pe = makeResourcePe();

  putTable(pe, 0x00, 0, 1);
  putEntry(pe, 0x10, 1, 0x80000000); // points back to the root table

  for (int attempt = 0; attempt < 2; attempt++) {
    auto parsed = parse(pe);
    REQUIRE(parsed == nullptr);
    REQUIRE(GetPEErr() == PEERR_RESC_CYCLE);
    REQUIRE(GetPEErrString() == "Resource directory contains a cycle");
  }
}

TEST_CASE("shared resource subtrees are parsed once, not rejected",
          "[resource]") {
  auto pe = makeResourcePe();

  // Two type entries referencing the same child table.
  putTable(pe, 0x00, 0, 2);
  putEntry(pe, 0x10, 10, 0x80000030);
  putEntry(pe, 0x18, 11, 0x80000030);

  putTable(pe, 0x30, 0, 1);
  putEntry(pe, 0x40, 1, 0x80000048);

  putTable(pe, 0x48, 0, 1);
  putEntry(pe, 0x58, 0x409, 0x60);

  putDataEntry(pe, 0x60, kSectionRva + 0x100, 4);
  putData(pe, 0x100, "ABCD");

  auto parsed = parse(pe);
  REQUIRE(parsed != nullptr);

  // The shared subtree is collected a single time.
  auto resources = collectResources(parsed.get());
  REQUIRE(resources.size() == 1);
  REQUIRE(resources[0].type == 10);
  REQUIRE(resources[0].name == 1);
  REQUIRE(resources[0].lang == 0x409);
}

TEST_CASE("resource depth limit is configurable and stable", "[resource]") {
  auto pe = makeResourcePe();

  // A chain of four directory tables, deeper than the Windows convention.
  putTable(pe, 0x00, 0, 1);
  putEntry(pe, 0x10, 1, 0x80000018);
  putTable(pe, 0x18, 0, 1);
  putEntry(pe, 0x28, 2, 0x80000030);
  putTable(pe, 0x30, 0, 1);
  putEntry(pe, 0x40, 3, 0x80000048);
  putTable(pe, 0x48, 0, 1);
  putEntry(pe, 0x58, 0x409, 0x60);
  putDataEntry(pe, 0x60, kSectionRva + 0x100, 4);
  putData(pe, 0x100, "ABCD");

  {
    // The default depth limit of three rejects the fourth level.
    auto parsed = parse(pe);
    REQUIRE(parsed == nullptr);
    REQUIRE(GetPEErr() == PEERR_RESC_DEPTH);
    REQUIRE(GetPEErrString() == "Resource directory too deep");
  }

  {
    LimitsGuard guard;
    auto limits = GetResourceParseLimits();
    limits.maxDepth = 4;
    SetResourceParseLimits(limits);

    auto parsed = parse(pe);
    REQUIRE(parsed != nullptr);
    REQUIRE(collectResources(parsed.get()).size() == 1);
  }

  // The guard restored the default limit.
  REQUIRE(GetResourceParseLimits().maxDepth == 3);
}

TEST_CASE("resource node limit produces a stable error", "[resource]") {
  LimitsGuard guard;
  auto pe = makeNormalTreePe();

  auto limits = GetResourceParseLimits();
  limits.maxNodes = 2; // the tree holds four entries
  SetResourceParseLimits(limits);

  for (int attempt = 0; attempt < 2; attempt++) {
    auto parsed = parse(pe);
    REQUIRE(parsed == nullptr);
    REQUIRE(GetPEErr() == PEERR_RESC_NODES);
    REQUIRE(GetPEErrString() == "Too many resource directory entries");
  }
}

TEST_CASE("resource read work limit produces a stable error", "[resource]") {
  LimitsGuard guard;
  auto pe = makeNormalTreePe();

  auto limits = GetResourceParseLimits();
  limits.maxReadBytes = 8; // smaller than one directory table header
  SetResourceParseLimits(limits);

  for (int attempt = 0; attempt < 2; attempt++) {
    auto parsed = parse(pe);
    REQUIRE(parsed == nullptr);
    REQUIRE(GetPEErr() == PEERR_RESC_WORK);
    REQUIRE(GetPEErrString() == "Resource directory read limit exceeded");
  }
}

TEST_CASE("resource parse limits round-trip through the accessors",
          "[resource]") {
  LimitsGuard guard;

  auto defaults = GetResourceParseLimits();
  REQUIRE(defaults.maxDepth == 3);
  REQUIRE(defaults.maxNodes == 65536);
  REQUIRE(defaults.maxReadBytes == 16 * 1024 * 1024);

  resource_parse_limits custom{8, 100, 4096};
  SetResourceParseLimits(custom);
  auto current = GetResourceParseLimits();
  REQUIRE(current.maxDepth == 8);
  REQUIRE(current.maxNodes == 100);
  REQUIRE(current.maxReadBytes == 4096);
}

} // namespace peparse
