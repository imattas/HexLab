#pragma once

#include "hexlab/loaders/jar.hpp"

namespace hexlab {

enum class JmodSection { classes, conf, headers, legal, lib, bin, include, man, unknown };

struct JmodMember {
    std::size_t archive_member_index = 0;
    JmodSection section = JmodSection::unknown;
    std::string path_in_section;
};

struct JmodArchive {
    JarArchive archive;
    std::vector<JmodMember> members;
    std::uint8_t major_version = 0;
    std::uint8_t minor_version = 0;
};

// Reads a JMOD v1.0 header and the ZIP archive following it. ZIP limits apply
// to the embedded archive; member indexes refer to archive.members.
HEXLAB_LOADERS_EXPORT Result<JmodArchive> read_jmod_archive(
    const ByteStorage &, std::stop_token = {}, JarLimits = {});

// Finds an exact slash-separated internal-name path under the classes/ section and loads it as
// a normal JVM class. Duplicate paths are reported as ambiguous.
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_jmod_class(
    const JmodArchive &, std::string_view internal_name, std::stop_token = {}, JarLimits = {});

} // namespace hexlab
