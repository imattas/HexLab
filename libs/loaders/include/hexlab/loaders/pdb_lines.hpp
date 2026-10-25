#pragma once
#include "hexlab/loaders/loaded_image.hpp"
#include "hexlab/types/pdb.hpp"
#include <filesystem>

namespace hexlab {
// Import C13 rows from an explicitly supplied PDB into a PE image. Rows are
// attached only when the PDB GUID and age match exactly one CodeView record.
// Section ordinals are one-based COFF ordinals; rows that exceed their
// contribution or declared PE section extent are retained without an address.
HEXLAB_LOADERS_EXPORT Result<std::size_t> attach_pdb_source_lines(
    LoadedImage &image, const types::PdbDatabase &pdb,
    const types::PdbSourceLineTable &lines);
// Attach local/parameter rows after the same exact identity match. Procedure
// addresses are mapped only when the complete procedure extent fits the PE.
HEXLAB_LOADERS_EXPORT Result<std::size_t> attach_pdb_locals(
    LoadedImage &image, const types::PdbDatabase &pdb,
    const types::PdbLocalTable &locals);
// Join exact module/IPI/file identities and map explicit-length inline ranges.
HEXLAB_LOADERS_EXPORT Result<std::size_t> attach_pdb_inline_sites(
    LoadedImage &, const types::PdbDatabase &, const types::PdbLocalTable &,
    const types::PdbSourceLineTable &);
// Binds one explicitly selected local PDB, recording missing/malformed/mismatch
// state in PE metadata. Never performs network access.
HEXLAB_LOADERS_EXPORT Result<bool> bind_local_pe_pdb(LoadedImage &, const std::filesystem::path &,
                                                    std::stop_token = {});
}
