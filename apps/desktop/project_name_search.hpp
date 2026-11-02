#pragma once

#include "jump_resolver.hpp"
#include "hexlab/workspace/project.hpp"

#include <atomic>
#include <filesystem>
#include <string>
#include <vector>

namespace hexlab::desktop {

struct ProjectNameRecord {
    std::string name;
    Location location;
    NamedLocationScope scope = NamedLocationScope::symbols;
    bool reference = false;
};

struct ProjectNameSource {
    std::filesystem::path path;
    database::ProjectUuid uuid{};
    InputIdentity input;
    database::ProjectRevisions revisions;
    std::optional<Sha256Digest> external_input_fingerprint;
    bool complete = true;
    std::vector<ProjectNameRecord> records;
};

struct ProjectFolderNameIndex {
    std::filesystem::path folder;
    std::vector<ProjectNameSource> projects;
    bool truncated = false;
    std::string limitation;
};

// Opens only direct-child `.hxproj` databases read-only. It reads their
// embedded input, never their recorded external source paths. A bounded
// per-user cache stores derived name/reference rows keyed to project UUID,
// input hash and byte/decision revisions.
Result<ProjectFolderNameIndex> index_project_folder_names(
    const std::filesystem::path &folder, const std::atomic_bool *cancelled);

NamedLocationSearch search_project_folder_names(
    const ProjectFolderNameIndex &, const wxString &, NamedLocationScope,
    NamedLocationSearchMode, const std::atomic_bool *cancelled = nullptr);

} // namespace hexlab::desktop
