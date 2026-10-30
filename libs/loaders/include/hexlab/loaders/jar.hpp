#pragma once
#include "hexlab/loaders/jvm.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace hexlab {

struct JarMember {
    std::string name;
    std::uint64_t compressed_size = 0;
    std::uint64_t uncompressed_size = 0;
    std::uint32_t crc32 = 0;
    std::uint64_t data_offset = 0;
    std::uint16_t compression_method = 0;
    bool directory = false;
    bool encrypted = false;
    bool supported = false;
};

struct JarLimits {
    std::uint64_t max_archive_bytes = 512ULL * 1024 * 1024;
    std::uint64_t max_member_bytes = 128ULL * 1024 * 1024;
    std::uint64_t max_total_uncompressed_bytes = 4ULL * 1024 * 1024 * 1024;
    std::size_t max_members = 100'000;
    std::size_t max_name_bytes = 4096;
    std::size_t max_volumes = 65'536;
};

struct JarArchive {
    std::shared_ptr<const std::vector<std::byte>> source;
    std::vector<JarMember> members;
};

// Reads and validates ZIP central directories across one or more ordered
// volumes using ZIP32 or bounded ZIP64 metadata. Volume order is disk-number
// order; the combined input remains bounded by JarLimits::max_archive_bytes.
// Entries using a data descriptor must provide matching CRC and sizes before
// the central directory.
HEXLAB_LOADERS_EXPORT Result<JarArchive> read_jar_archive(
    std::span<const std::shared_ptr<const ByteStorage>> volumes, std::stop_token = {}, JarLimits = {});
// Single-volume convenience overload.
// Reads the same bounded format from one ByteStorage. Encrypted entries,
// unsupported general-purpose flags, and compression methods other than
// stored/raw-DEFLATE remain visible in inventory where possible but cannot
// be opened as classes.
HEXLAB_LOADERS_EXPORT Result<JarArchive> read_jar_archive(const ByteStorage &, std::stop_token = {},
                                                         JarLimits = {});
// Extracts one member into bounded memory and verifies its uncompressed size and
// CRC-32 before returning it. Methods 0 (stored) and 8 (raw DEFLATE) are
// supported; the DEFLATE stream must consume the full compressed extent and
// produce exactly the declared uncompressed size.
HEXLAB_LOADERS_EXPORT Result<std::vector<std::byte>> extract_jar_member(
    const JarArchive &, std::size_t member_index, std::stop_token = {}, JarLimits = {});
// Extracts a .class member and runs the ordinary bounded class-file loader.
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_jvm_jar_class(
    const JarArchive &, std::size_t member_index, std::stop_token = {}, JarLimits = {});

} // namespace hexlab
