#include <pe-parse/parse.h>

#include <array>
#include <catch2/catch.hpp>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace peparse {
namespace {

constexpr std::uint32_t kNtHeaderOffset = 0x80;
constexpr std::uint32_t kSectionRva = 0x2000;
constexpr std::uint32_t kSectionRawOffset = 0x200;
constexpr std::uint32_t kSectionRawSize = 0x1200;
constexpr std::uint32_t kDebugDirectoryRva = 0x2f50;
constexpr std::uint32_t kDebugDataRva = 0x2fa4;
constexpr std::size_t kFileSize = kSectionRawOffset + kSectionRawSize;

using TestPe = std::array<std::uint8_t, kFileSize>;
using ParsedPePtr = std::unique_ptr<parsed_pe, void (*)(parsed_pe *)>;

struct ExportInfo {
  VA addr;
  std::uint16_t ordinal;
  std::string symbolName;
  std::string forwardName;
};

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
void putCString(T &buffer, std::size_t offset, const char *value) {
  while (*value != '\0') {
    buffer[offset++] = static_cast<std::uint8_t>(*value++);
  }
  buffer[offset] = 0;
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

std::uint32_t sectionEndRva() {
  return kSectionRva + kSectionRawSize;
}

std::size_t sectionOffset(std::uint32_t rva) {
  return kSectionRawOffset + (rva - kSectionRva);
}

std::size_t sectionOffset(std::uint32_t sectionRva, std::uint32_t rva) {
  return kSectionRawOffset + (rva - sectionRva);
}

std::uint32_t sectionRvaAt(std::uint32_t sectionRva, std::uint32_t offset) {
  return sectionRva + offset;
}

std::size_t debugEntryOffset() {
  return sectionOffset(kDebugDirectoryRva);
}

void putSectionRawRange(TestPe &pe,
                        std::uint32_t rawOffset,
                        std::uint32_t rawSize) {
  constexpr auto kSectionHeaderOffset = sectionHeaderOffset();
  put32(pe,
        kSectionHeaderOffset + offsetof(image_section_header, SizeOfRawData),
        rawSize);
  put32(pe,
        kSectionHeaderOffset + offsetof(image_section_header, PointerToRawData),
        rawOffset);
}

void putDebugEntry(TestPe &pe,
                   std::uint32_t sizeOfData,
                   std::uint32_t addressOfRawData) {
  put32(pe,
        debugEntryOffset() + offsetof(debug_dir_entry, SizeOfData),
        sizeOfData);
  put32(pe,
        debugEntryOffset() + offsetof(debug_dir_entry, AddressOfRawData),
        addressOfRawData);
}

void putExportDirectoryDword(TestPe &pe,
                             std::uint32_t exportSectionRva,
                             std::size_t fieldOffset,
                             std::uint32_t value) {
  put32(pe,
        sectionOffset(exportSectionRva, exportSectionRva) + fieldOffset,
        value);
}

void putExportDword(TestPe &pe,
                    std::uint32_t exportSectionRva,
                    std::uint32_t rva,
                    std::uint32_t value) {
  put32(pe, sectionOffset(exportSectionRva, rva), value);
}

void putExportWord(TestPe &pe,
                   std::uint32_t exportSectionRva,
                   std::uint32_t rva,
                   std::uint16_t value) {
  put16(pe, sectionOffset(exportSectionRva, rva), value);
}

void putExportCString(TestPe &pe,
                      std::uint32_t exportSectionRva,
                      std::uint32_t rva,
                      const char *value) {
  putCString(pe, sectionOffset(exportSectionRva, rva), value);
}

TestPe makeMinimalPe(std::uint32_t sectionRva = kSectionRva,
                     std::uint32_t sectionRawSize = kSectionRawSize) {
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
        sectionRawSize);
  put32(pe,
        kSectionHeaderOffset + offsetof(image_section_header, VirtualAddress),
        sectionRva);
  putSectionRawRange(pe, kSectionRawOffset, sectionRawSize);

  return pe;
}

ParsedPePtr parse(TestPe &pe) {
  return ParsedPePtr(
      ParsePEFromPointer(pe.data(), static_cast<std::uint32_t>(pe.size())),
      DestructParsedPE);
}

struct ImportInfo {
  VA addr;
  std::string moduleName;
  std::string symbolName;
};

enum class Bitness { Pe32, Pe32Plus };
enum class ImportTarget { Descriptor, Name, Thunk };
enum class BoundaryEnd { Section, File };

constexpr std::uint32_t kImportSectionRva = kSectionRva;
constexpr std::uint32_t kImportSectionRawOffset = kSectionRawOffset;
constexpr std::uint32_t kImportGuardSize = 0x200;
constexpr std::uint32_t kImportValidDescriptorOffset = 0;
constexpr std::uint32_t kImportBoundaryDescriptorOffset = 0x14;
constexpr std::uint32_t kImportDescriptorTerminatorOffset = 0x28;
constexpr std::uint32_t kImportAddressTableOffset = 0x40;
constexpr std::uint32_t kImportLookupTableOffset = 0x60;
constexpr std::uint32_t kImportSymbolOffset = 0x80;
constexpr std::uint32_t kImportModuleOffset = 0x90;

void put64(std::vector<std::uint8_t> &buffer,
           std::size_t offset,
           std::uint64_t value) {
  for (std::size_t i = 0; i < sizeof(value); ++i) {
    buffer[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
  }
}

std::size_t importOptionalHeaderOffset() {
  return optionalHeaderOffset();
}

std::size_t importSectionHeaderOffset(Bitness bitness) {
  if (bitness == Bitness::Pe32) {
    return sectionHeaderOffset();
  }

  return importOptionalHeaderOffset() + sizeof(optional_header_64);
}

std::size_t importDataDirectoryOffset(Bitness bitness,
                                      data_directory_kind kind) {
  const auto optionalOffset = importOptionalHeaderOffset();
  const auto dataDirectoryMember =
      bitness == Bitness::Pe32 ? offsetof(optional_header_32, DataDirectory)
                               : offsetof(optional_header_64, DataDirectory);
  return optionalOffset + dataDirectoryMember +
         (static_cast<std::size_t>(kind) * sizeof(data_directory));
}

void putImportDataDirectory(std::vector<std::uint8_t> &pe,
                            Bitness bitness,
                            data_directory_kind kind,
                            std::uint32_t virtualAddress,
                            std::uint32_t size) {
  const auto offset = importDataDirectoryOffset(bitness, kind);
  put32(pe, offset + offsetof(data_directory, VirtualAddress), virtualAddress);
  put32(pe, offset + offsetof(data_directory, Size), size);
}

std::uint32_t importThunkWidth(Bitness bitness) {
  return bitness == Bitness::Pe32 ? sizeof(std::uint32_t)
                                  : sizeof(std::uint64_t);
}

std::uint32_t targetStructWidth(Bitness bitness, ImportTarget target) {
  switch (target) {
  case ImportTarget::Descriptor:
    return sizeof(import_dir_entry);
  case ImportTarget::Name:
    return 1;
  case ImportTarget::Thunk:
    return importThunkWidth(bitness);
  }

  return 0;
}

std::uint32_t rvaForImportOffset(std::uint32_t sectionOffset) {
  return kImportSectionRva + sectionOffset;
}

std::uint32_t fileOffsetForImportRva(std::uint32_t rva) {
  return kImportSectionRawOffset + (rva - kImportSectionRva);
}

std::vector<std::uint8_t>
makeMinimalImportPe(Bitness bitness,
                    std::uint32_t sectionRawSize,
                    std::uint32_t backingSize = kFileSize) {
  std::vector<std::uint8_t> pe(backingSize, 0);

  put16(pe, offsetof(dos_header, e_magic), MZ_MAGIC);
  put32(pe, offsetof(dos_header, e_lfanew), kNtHeaderOffset);
  put32(pe, kNtHeaderOffset, NT_MAGIC);

  const auto fileHeaderOffset =
      kNtHeaderOffset + offsetof(nt_header_32, FileHeader);
  put16(pe,
        fileHeaderOffset + offsetof(file_header, Machine),
        bitness == Bitness::Pe32 ? IMAGE_FILE_MACHINE_I386
                                 : IMAGE_FILE_MACHINE_AMD64);
  put16(pe, fileHeaderOffset + offsetof(file_header, NumberOfSections), 1);

  const auto optionalOffset = importOptionalHeaderOffset();
  put16(pe,
        optionalOffset,
        bitness == Bitness::Pe32 ? NT_OPTIONAL_32_MAGIC
                                 : NT_OPTIONAL_64_MAGIC);

  if (bitness == Bitness::Pe32) {
    put32(pe,
          optionalOffset + offsetof(optional_header_32, ImageBase),
          0x400000);
    put32(pe,
          optionalOffset +
              offsetof(optional_header_32, NumberOfRvaAndSizes),
          NUM_DIR_ENTRIES);
  } else {
    put64(pe,
          optionalOffset + offsetof(optional_header_64, ImageBase),
          0x140000000ULL);
    put32(pe,
          optionalOffset +
              offsetof(optional_header_64, NumberOfRvaAndSizes),
          NUM_DIR_ENTRIES);
  }

  const auto sectionHeader = importSectionHeaderOffset(bitness);
  const std::array<std::uint8_t, 8> sectionName{'.', 't', 'e', 's', 't', 0};
  for (std::size_t i = 0; i < sectionName.size(); ++i) {
    pe[sectionHeader + i] = sectionName[i];
  }
  put32(pe,
        sectionHeader + offsetof(image_section_header, Misc.VirtualSize),
        kSectionRawSize);
  put32(pe,
        sectionHeader + offsetof(image_section_header, VirtualAddress),
        kImportSectionRva);
  put32(pe,
        sectionHeader + offsetof(image_section_header, SizeOfRawData),
        sectionRawSize);
  put32(pe,
        sectionHeader + offsetof(image_section_header, PointerToRawData),
        kImportSectionRawOffset);

  return pe;
}

ParsedPePtr parseImportPe(std::vector<std::uint8_t> &pe,
                          std::uint32_t parseSize = 0) {
  const auto size = parseSize == 0 ? static_cast<std::uint32_t>(pe.size())
                                   : parseSize;
  return ParsedPePtr(ParsePEFromPointer(pe.data(), size),
                     DestructParsedPE);
}

void putImportDescriptor(std::vector<std::uint8_t> &pe,
                         std::uint32_t descriptorOffset,
                         std::uint32_t lookupRva,
                         std::uint32_t nameRva,
                         std::uint32_t addressRva) {
  const auto fileOffset = fileOffsetForImportRva(
      rvaForImportOffset(descriptorOffset));
  put32(pe,
        fileOffset + offsetof(import_dir_entry, LookupTableRVA),
        lookupRva);
  put32(pe, fileOffset + offsetof(import_dir_entry, TimeStamp), 0);
  put32(pe, fileOffset + offsetof(import_dir_entry, ForwarderChain), 0);
  put32(pe, fileOffset + offsetof(import_dir_entry, NameRVA), nameRva);
  put32(pe,
        fileOffset + offsetof(import_dir_entry, AddressRVA),
        addressRva);
}

std::vector<std::uint8_t>
makeTruncatedImportPe(Bitness bitness,
                      ImportTarget target,
                      BoundaryEnd boundaryEnd,
                      bool completeAtBoundary) {
  const auto width = targetStructWidth(bitness, target);
  const auto targetOffset = kSectionRawSize - kImportGuardSize;
  const auto sectionEnd = targetOffset + (completeAtBoundary ? width
                                                             : width - 1);

  const auto sectionRawSize = sectionEnd;
  const auto backingSize = kFileSize;

  auto pe = makeMinimalImportPe(bitness, sectionRawSize, backingSize);

  for (std::uint32_t i = kImportSectionRawOffset; i < backingSize; ++i) {
    pe[i] = 0xcd;
  }

  const auto lookupRva = rvaForImportOffset(kImportLookupTableOffset);
  const auto addressRva = rvaForImportOffset(kImportAddressTableOffset);
  const auto moduleRva = rvaForImportOffset(kImportModuleOffset);
  const auto symbolRva = rvaForImportOffset(kImportSymbolOffset);

  putCString(pe,
             fileOffsetForImportRva(symbolRva) + sizeof(std::uint16_t),
             "ValidSymbol");
  putCString(pe, fileOffsetForImportRva(moduleRva), "VALID.DLL");

  if (bitness == Bitness::Pe32) {
    put32(pe, fileOffsetForImportRva(lookupRva), symbolRva);
    put32(pe, fileOffsetForImportRva(lookupRva) + sizeof(std::uint32_t), 0);
    put32(pe, fileOffsetForImportRva(addressRva), symbolRva);
    put32(pe, fileOffsetForImportRva(addressRva) + sizeof(std::uint32_t), 0);
  } else {
    put64(pe, fileOffsetForImportRva(lookupRva), symbolRva);
    put64(pe,
          fileOffsetForImportRva(lookupRva) + sizeof(std::uint64_t),
          0);
    put64(pe, fileOffsetForImportRva(addressRva), symbolRva);
    put64(pe,
          fileOffsetForImportRva(addressRva) + sizeof(std::uint64_t),
          0);
  }

  putImportDescriptor(pe,
                      kImportValidDescriptorOffset,
                      lookupRva,
                      moduleRva,
                      addressRva);

  const auto targetRva = rvaForImportOffset(targetOffset);
  switch (target) {
  case ImportTarget::Descriptor:
    putImportDataDirectory(pe,
                           bitness,
                           DIR_IMPORT,
                           targetRva,
                           static_cast<std::uint32_t>(width * 2));
    if (completeAtBoundary) {
      std::fill(pe.begin() + fileOffsetForImportRva(targetRva),
                pe.begin() + fileOffsetForImportRva(targetRva) + width,
                0);
    }
    break;
  case ImportTarget::Name:
    putImportDataDirectory(pe,
                           bitness,
                           DIR_IMPORT,
                           kImportSectionRva,
                           sizeof(import_dir_entry) * 3);
    putImportDescriptor(pe,
                        kImportBoundaryDescriptorOffset,
                        lookupRva,
                        targetRva,
                        addressRva);
    if (completeAtBoundary) {
      pe[fileOffsetForImportRva(targetRva)] = 0;
    }
    break;
  case ImportTarget::Thunk:
    putImportDataDirectory(pe,
                           bitness,
                           DIR_IMPORT,
                           kImportSectionRva,
                           sizeof(import_dir_entry) * 3);
    putImportDescriptor(pe,
                        kImportBoundaryDescriptorOffset,
                        targetRva,
                        moduleRva,
                        addressRva);
    if (completeAtBoundary) {
      if (bitness == Bitness::Pe32) {
        put32(pe, fileOffsetForImportRva(targetRva), 0);
      } else {
        put64(pe, fileOffsetForImportRva(targetRva), 0);
      }
    }
    break;
  }

  if (completeAtBoundary && target != ImportTarget::Descriptor) {
    std::fill(pe.begin() +
                  fileOffsetForImportRva(
                      rvaForImportOffset(kImportDescriptorTerminatorOffset)),
              pe.begin() +
                  fileOffsetForImportRva(
                      rvaForImportOffset(kImportDescriptorTerminatorOffset +
                                         sizeof(import_dir_entry))),
              0);
  }

  return pe;
}

int captureImport(void *ctx,
                  const VA &addr,
                  const std::string &moduleName,
                  const std::string &symbolName) {
  auto *imports = static_cast<std::vector<ImportInfo> *>(ctx);
  imports->push_back({addr, moduleName, symbolName});
  return 0;
}

std::uint32_t importSampleParseSize(Bitness bitness,
                                    ImportTarget target,
                                    BoundaryEnd boundaryEnd,
                                    bool completeAtBoundary) {
  if (boundaryEnd == BoundaryEnd::Section) {
    return kFileSize;
  }

  const auto width = targetStructWidth(bitness, target);
  const auto targetOffset = kSectionRawSize - kImportGuardSize;
  return kImportSectionRawOffset + targetOffset +
         (completeAtBoundary ? width : width - 1);
}

int countDebugDirectory(void *ctx,
                        const std::uint32_t &,
                        const bounded_buffer *) {
  auto *count = static_cast<std::size_t *>(ctx);
  ++(*count);
  return 0;
}

int captureDebugDataSize(void *ctx,
                         const std::uint32_t &,
                         const bounded_buffer *data) {
  auto *sizes = static_cast<std::vector<std::uint32_t> *>(ctx);
  sizes->push_back(data->bufLen);
  return 0;
}

int captureExport(void *ctx,
                  const VA &addr,
                  std::uint16_t ordinal,
                  const std::string &,
                  const std::string &symbolName,
                  const std::string &forwardName) {
  auto *exports = static_cast<std::vector<ExportInfo> *>(ctx);
  exports->push_back({addr, ordinal, symbolName, forwardName});
  return 0;
}

} // namespace

TEST_CASE("splitBufferByLength enforces exact range boundaries", "[buffer]") {
  std::array<std::uint8_t, 8> bytes{{0, 1, 2, 3, 4, 5, 6, 7}};
  auto *buffer = makeBufferFromPointer(
      bytes.data(), static_cast<std::uint32_t>(bytes.size()));
  REQUIRE(buffer != nullptr);
  buffer->swapBytes = true;

  auto *slice = splitBufferByLength(buffer, 4, 4);
  REQUIRE(slice != nullptr);
  REQUIRE(slice->buf == bytes.data() + 4);
  REQUIRE(slice->bufLen == 4);
  REQUIRE(slice->copy);
  REQUIRE(slice->swapBytes);
  REQUIRE(slice->detail == nullptr);
  deleteBuffer(slice);

  auto *empty =
      splitBufferByLength(buffer, static_cast<std::uint32_t>(bytes.size()), 0);
  REQUIRE(empty != nullptr);
  REQUIRE(empty->buf == bytes.data() + bytes.size());
  REQUIRE(empty->bufLen == 0);
  REQUIRE(empty->copy);
  REQUIRE(empty->swapBytes);
  REQUIRE(empty->detail == nullptr);
  deleteBuffer(empty);

  REQUIRE(splitBufferByLength(buffer, 5, 4) == nullptr);
  REQUIRE(splitBufferByLength(
              buffer, 4, std::numeric_limits<std::uint32_t>::max()) == nullptr);

  auto *legacySlice = splitBuffer(buffer, 2, 6);
  REQUIRE(legacySlice != nullptr);
  REQUIRE(legacySlice->buf == bytes.data() + 2);
  REQUIRE(legacySlice->bufLen == 4);
  REQUIRE(legacySlice->copy);
  REQUIRE(legacySlice->swapBytes);
  REQUIRE(legacySlice->detail == nullptr);
  deleteBuffer(legacySlice);

  REQUIRE(splitBuffer(buffer, 6, 2) == nullptr);
  deleteBuffer(buffer);
}

TEST_CASE("oversized section raw data range is rejected", "[sections]") {
  auto pe = makeMinimalPe();
  putSectionRawRange(pe, static_cast<std::uint32_t>(kFileSize - 4), 5);

  auto p = parse(pe);

  REQUIRE_FALSE(p);
  REQUIRE(GetPEErr() == PEERR_SECT);
}

TEST_CASE("debug directory data can end at section boundary", "[debug]") {
  auto pe = makeMinimalPe();
  putDataDirectory(pe, DIR_DEBUG, kDebugDirectoryRva, sizeof(debug_dir_entry));
  putDebugEntry(pe, 4, sectionEndRva() - 4);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<std::uint32_t> sizes;
  IterDebugs(p.get(), captureDebugDataSize, &sizes);
  REQUIRE(sizes == std::vector<std::uint32_t>{4});
}

TEST_CASE("oversized debug directory data range is skipped", "[debug]") {
  auto pe = makeMinimalPe();
  putDataDirectory(pe, DIR_DEBUG, kDebugDirectoryRva, sizeof(debug_dir_entry));
  putDebugEntry(pe, 5, sectionEndRva() - 4);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::size_t debugDirectoryCount = 0;
  IterDebugs(p.get(), countDebugDirectory, &debugDirectoryCount);
  REQUIRE(debugDirectoryCount == 0);
}

TEST_CASE("overflowing debug directory data range is skipped", "[debug]") {
  auto pe = makeMinimalPe();
  putDataDirectory(pe, DIR_DEBUG, kDebugDirectoryRva, sizeof(debug_dir_entry));
  putDebugEntry(pe, std::numeric_limits<std::uint32_t>::max(), kDebugDataRva);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::size_t debugDirectoryCount = 0;
  IterDebugs(p.get(), countDebugDirectory, &debugDirectoryCount);
  REQUIRE(debugDirectoryCount == 0);
}

TEST_CASE("data directory entry can end at section boundary",
          "[data_directory]") {
  auto pe = makeMinimalPe();
  putDataDirectory(pe, DIR_LOAD_CONFIG, sectionEndRva() - 4, 4);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<std::uint8_t> rawEntry;
  REQUIRE(GetDataDirectoryEntry(p.get(), DIR_LOAD_CONFIG, rawEntry));
  REQUIRE(rawEntry.size() == 4);
}

TEST_CASE("oversized data directory entry is rejected", "[data_directory]") {
  auto pe = makeMinimalPe();
  putDataDirectory(pe, DIR_LOAD_CONFIG, sectionEndRva() - 4, 5);

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<std::uint8_t> rawEntry;
  REQUIRE_FALSE(GetDataDirectoryEntry(p.get(), DIR_LOAD_CONFIG, rawEntry));
  REQUIRE(GetPEErr() == PEERR_SIZE);
  REQUIRE(rawEntry.empty());
}

TEST_CASE("overflowing export directory range can contain forwarded exports",
          "[exports]") {
  constexpr std::uint32_t kExportSectionRva = 0xffffff00;
  constexpr std::uint32_t kExportDirectorySize = 0x200;

  auto pe = makeMinimalPe(kExportSectionRva, kExportDirectorySize);
  putDataDirectory(pe, DIR_EXPORT, kExportSectionRva, kExportDirectorySize);

  constexpr std::uint32_t kAddressTableOffset = 0x40;
  constexpr std::uint32_t kNamePointerOffset = 0x50;
  constexpr std::uint32_t kOrdinalTableOffset = 0x60;
  constexpr std::uint32_t kExportNameOffset = 0x70;
  constexpr std::uint32_t kModuleNameOffset = 0x80;
  constexpr std::uint32_t kForwardNameOffset = 0x90;

  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NameRVA),
                          sectionRvaAt(kExportSectionRva, kModuleNameOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NumberOfNamePointers),
                          1);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, AddressTableEntries),
                          1);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, ExportAddressTableRVA),
                          sectionRvaAt(kExportSectionRva, kAddressTableOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NamePointerRVA),
                          sectionRvaAt(kExportSectionRva, kNamePointerOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, OrdinalTableRVA),
                          sectionRvaAt(kExportSectionRva, kOrdinalTableOffset));

  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kAddressTableOffset),
                 sectionRvaAt(kExportSectionRva, kForwardNameOffset));
  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kNamePointerOffset),
                 sectionRvaAt(kExportSectionRva, kExportNameOffset));
  putExportWord(pe,
                kExportSectionRva,
                sectionRvaAt(kExportSectionRva, kOrdinalTableOffset),
                0);
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kExportNameOffset),
                   "Exported");
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kModuleNameOffset),
                   "module.dll");
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kForwardNameOffset),
                   "target.dll.Func");

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<ExportInfo> exports;
  IterExpFull(p.get(), captureExport, &exports);

  REQUIRE(exports.size() == 1);
  REQUIRE(exports[0].addr == 0);
  REQUIRE(exports[0].forwardName == "target.dll.Func");
}

TEST_CASE("ordinal-only exports are included", "[exports]") {
  constexpr std::uint32_t kExportSectionRva = kSectionRva;
  constexpr std::uint32_t kExportDirectorySize = 0x100;
  constexpr std::uint32_t kAddressTableOffset = 0x40;
  constexpr std::uint32_t kModuleNameOffset = 0x80;
  constexpr std::uint32_t kExportTargetRva = kExportSectionRva + 0x300;

  auto pe = makeMinimalPe(kExportSectionRva);
  putDataDirectory(pe, DIR_EXPORT, kExportSectionRva, kExportDirectorySize);

  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NameRVA),
                          sectionRvaAt(kExportSectionRva, kModuleNameOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, AddressTableEntries),
                          1);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NumberOfNamePointers),
                          0);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, ExportAddressTableRVA),
                          sectionRvaAt(kExportSectionRva, kAddressTableOffset));

  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kAddressTableOffset),
                 kExportTargetRva);
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kModuleNameOffset),
                   "module.dll");

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<ExportInfo> exports;
  IterExpFull(p.get(), captureExport, &exports);

  REQUIRE(exports.size() == 1);
  REQUIRE(exports[0].addr == kExportTargetRva);
  REQUIRE(exports[0].ordinal == 0);
  REQUIRE(exports[0].symbolName.empty());
  REQUIRE(exports[0].forwardName.empty());
}

TEST_CASE("empty ordinal-only export slots are skipped", "[exports]") {
  constexpr std::uint32_t kExportSectionRva = kSectionRva;
  constexpr std::uint32_t kExportDirectorySize = 0x100;
  constexpr std::uint32_t kAddressTableOffset = 0x40;
  constexpr std::uint32_t kModuleNameOffset = 0x80;
  constexpr std::uint32_t kExportTargetRva = kExportSectionRva + 0x300;

  auto pe = makeMinimalPe(kExportSectionRva);
  putDataDirectory(pe, DIR_EXPORT, kExportSectionRva, kExportDirectorySize);

  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NameRVA),
                          sectionRvaAt(kExportSectionRva, kModuleNameOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, AddressTableEntries),
                          2);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NumberOfNamePointers),
                          0);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, ExportAddressTableRVA),
                          sectionRvaAt(kExportSectionRva, kAddressTableOffset));

  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kAddressTableOffset),
                 0);
  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kAddressTableOffset + 4),
                 kExportTargetRva);
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kModuleNameOffset),
                   "module.dll");

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<ExportInfo> exports;
  IterExpFull(p.get(), captureExport, &exports);

  REQUIRE(exports.size() == 1);
  REQUIRE(exports[0].addr == kExportTargetRva);
  REQUIRE(exports[0].ordinal == 1);
  REQUIRE(exports[0].symbolName.empty());
  REQUIRE(exports[0].forwardName.empty());
}

TEST_CASE("mixed named and ordinal-only exports are included once",
          "[exports]") {
  constexpr std::uint32_t kExportSectionRva = kSectionRva;
  constexpr std::uint32_t kExportDirectorySize = 0x180;
  constexpr std::uint32_t kAddressTableOffset = 0x40;
  constexpr std::uint32_t kNamePointerOffset = 0x60;
  constexpr std::uint32_t kOrdinalTableOffset = 0x70;
  constexpr std::uint32_t kNameTwoOffset = 0x80;
  constexpr std::uint32_t kNameZeroOffset = 0x90;
  constexpr std::uint32_t kModuleNameOffset = 0xa0;
  constexpr std::uint32_t kForwardNameOffset = 0xb0;
  constexpr std::uint32_t kNamedZeroTargetRva = kExportSectionRva + 0x300;
  constexpr std::uint32_t kNamedTwoTargetRva = kExportSectionRva + 0x304;

  auto pe = makeMinimalPe(kExportSectionRva);
  putDataDirectory(pe, DIR_EXPORT, kExportSectionRva, kExportDirectorySize);

  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NameRVA),
                          sectionRvaAt(kExportSectionRva, kModuleNameOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, AddressTableEntries),
                          3);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NumberOfNamePointers),
                          2);
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, ExportAddressTableRVA),
                          sectionRvaAt(kExportSectionRva, kAddressTableOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, NamePointerRVA),
                          sectionRvaAt(kExportSectionRva, kNamePointerOffset));
  putExportDirectoryDword(pe,
                          kExportSectionRva,
                          offsetof(export_dir_table, OrdinalTableRVA),
                          sectionRvaAt(kExportSectionRva, kOrdinalTableOffset));

  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kAddressTableOffset),
                 kNamedZeroTargetRva);
  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kAddressTableOffset + 4),
                 sectionRvaAt(kExportSectionRva, kForwardNameOffset));
  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kAddressTableOffset + 8),
                 kNamedTwoTargetRva);

  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kNamePointerOffset),
                 sectionRvaAt(kExportSectionRva, kNameTwoOffset));
  putExportDword(pe,
                 kExportSectionRva,
                 sectionRvaAt(kExportSectionRva, kNamePointerOffset + 4),
                 sectionRvaAt(kExportSectionRva, kNameZeroOffset));
  putExportWord(pe,
                kExportSectionRva,
                sectionRvaAt(kExportSectionRva, kOrdinalTableOffset),
                2);
  putExportWord(pe,
                kExportSectionRva,
                sectionRvaAt(kExportSectionRva, kOrdinalTableOffset + 2),
                0);

  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kNameTwoOffset),
                   "NamedTwo");
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kNameZeroOffset),
                   "NamedZero");
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kModuleNameOffset),
                   "module.dll");
  putExportCString(pe,
                   kExportSectionRva,
                   sectionRvaAt(kExportSectionRva, kForwardNameOffset),
                   "target.dll.Func");

  auto p = parse(pe);
  INFO(GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(p);

  std::vector<ExportInfo> exports;
  IterExpFull(p.get(), captureExport, &exports);

  REQUIRE(exports.size() == 3);
  REQUIRE(exports[0].addr == kNamedTwoTargetRva);
  REQUIRE(exports[0].ordinal == 2);
  REQUIRE(exports[0].symbolName == "NamedTwo");
  REQUIRE(exports[0].forwardName.empty());
  REQUIRE(exports[1].addr == kNamedZeroTargetRva);
  REQUIRE(exports[1].ordinal == 0);
  REQUIRE(exports[1].symbolName == "NamedZero");
  REQUIRE(exports[1].forwardName.empty());
  REQUIRE(exports[2].addr == 0);
  REQUIRE(exports[2].ordinal == 1);
  REQUIRE(exports[2].symbolName.empty());
  REQUIRE(exports[2].forwardName == "target.dll.Func");
}

TEST_CASE("import structures ending exactly at a boundary are accepted",
          "[imports]") {
  const auto bitness = GENERATE(Bitness::Pe32, Bitness::Pe32Plus);
  const auto target =
      GENERATE(ImportTarget::Descriptor, ImportTarget::Name,
               ImportTarget::Thunk);
  const auto boundaryEnd =
      GENERATE(BoundaryEnd::Section, BoundaryEnd::File);

  auto pe = makeTruncatedImportPe(bitness, target, boundaryEnd, true);
  const auto sampleParseSize =
      importSampleParseSize(bitness, target, boundaryEnd, true);
  auto parsed = parseImportPe(pe, sampleParseSize);

  INFO("bitness=" << static_cast<int>(bitness)
                       << " target=" << static_cast<int>(target)
                       << " end=" << static_cast<int>(boundaryEnd) << " "
                       << GetPEErrString() << " at " << GetPEErrLoc());
  REQUIRE(parsed);

  std::vector<ImportInfo> imports;
  IterImpVAString(parsed.get(), captureImport, &imports);

  if (target == ImportTarget::Descriptor) {
    REQUIRE(imports.empty());
  } else {
    REQUIRE(imports.size() == (target == ImportTarget::Name ? 2U : 1U));
    for (std::size_t i = 0; i < imports.size(); ++i) {
      REQUIRE(imports[i].moduleName ==
              (target == ImportTarget::Name && i == imports.size() - 1
                   ? ""
                   : "VALID.DLL"));
      REQUIRE(imports[i].symbolName == "ValidSymbol");
    }

    const auto imageBase = bitness == Bitness::Pe32 ? 0x400000ULL
                                                    : 0x140000000ULL;
    REQUIRE(imports.front().addr ==
            imageBase + kImportSectionRva + kImportAddressTableOffset);
  }
}

TEST_CASE("truncated import structures do not expose forged imports",
          "[imports]") {
  const auto bitness = GENERATE(Bitness::Pe32, Bitness::Pe32Plus);
  const auto target =
      GENERATE(ImportTarget::Descriptor, ImportTarget::Name,
               ImportTarget::Thunk);
  const auto boundaryEnd =
      GENERATE(BoundaryEnd::Section, BoundaryEnd::File);

  for (int iteration = 0; iteration < 5; ++iteration) {
    auto pe = makeTruncatedImportPe(bitness, target, boundaryEnd, false);
    auto parsed = parseImportPe(
        pe,
        importSampleParseSize(bitness, target, boundaryEnd, false));

    INFO("iteration=" << iteration << " " << GetPEErrString() << " at "
                      << GetPEErrLoc());
    REQUIRE_FALSE(parsed);

    std::vector<ImportInfo> imports;
    REQUIRE(imports.empty());
  }
}

TEST_CASE("maximum import RVAs cannot create integer-boundary aliases",
          "[imports]") {
  const auto bitness = GENERATE(Bitness::Pe32, Bitness::Pe32Plus);
  constexpr std::uint32_t kMaxRva =
      std::numeric_limits<std::uint32_t>::max();

  SECTION("module name RVA") {
    auto pe = makeMinimalImportPe(bitness, kSectionRawSize);
    const auto lookupRva = rvaForImportOffset(kImportLookupTableOffset);
    const auto addressRva = rvaForImportOffset(kImportAddressTableOffset);

    putImportDescriptor(pe,
                        0,
                        lookupRva,
                        kMaxRva,
                        addressRva);
    putImportDataDirectory(pe,
                           bitness,
                           DIR_IMPORT,
                           kImportSectionRva,
                           sizeof(import_dir_entry) * 2);

    auto parsed = parseImportPe(pe);
    REQUIRE_FALSE(parsed);
  }

  SECTION("lookup table RVA") {
    auto pe = makeMinimalImportPe(bitness, kSectionRawSize);
    const auto moduleRva = rvaForImportOffset(kImportModuleOffset);
    const auto addressRva = rvaForImportOffset(kImportAddressTableOffset);

    putCString(pe, fileOffsetForImportRva(moduleRva), "VALID.DLL");
    putImportDescriptor(pe, 0, kMaxRva, moduleRva, addressRva);
    putImportDataDirectory(pe,
                           bitness,
                           DIR_IMPORT,
                           kImportSectionRva,
                           sizeof(import_dir_entry) * 2);

    auto parsed = parseImportPe(pe);
    REQUIRE_FALSE(parsed);
  }

  SECTION("thunk value") {
    auto pe = makeMinimalImportPe(bitness, kSectionRawSize);
    const auto lookupRva = rvaForImportOffset(kImportLookupTableOffset);
    const auto addressRva = rvaForImportOffset(kImportAddressTableOffset);
    const auto moduleRva = rvaForImportOffset(kImportModuleOffset);

    putCString(pe, fileOffsetForImportRva(moduleRva), "VALID.DLL");
    putImportDescriptor(pe, 0, lookupRva, moduleRva, addressRva);
    putImportDataDirectory(pe,
                           bitness,
                           DIR_IMPORT,
                           kImportSectionRva,
                           sizeof(import_dir_entry) * 2);

    put32(pe,
          fileOffsetForImportRva(lookupRva),
          kMaxRva & ~std::uint32_t{0x80000000});
  if (bitness == Bitness::Pe32Plus) {
    put32(pe,
          fileOffsetForImportRva(lookupRva) + sizeof(std::uint32_t),
          0);
  }

    auto parsed = parseImportPe(pe);
    REQUIRE_FALSE(parsed);
  }
}

} // namespace peparse
