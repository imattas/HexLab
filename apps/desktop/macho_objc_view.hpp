#pragma once

#include "hexlab/analysis/macho_objc.hpp"
#include "hexlab/workspace/commands.hpp"
#include "hexlab/image/image.hpp"
#include <wx/string.h>
#include <optional>
#include <string>
#include <vector>

namespace hexlab::desktop {

struct MachOObjCViewRow {
    std::string kind;
    std::string owner;
    std::string name;
    std::string status;
    std::string provenance;
    std::string details;
    std::optional<Address> address;
    std::optional<Address> code_address;
};

inline constexpr std::size_t macho_objc_view_row_limit = 250000;

std::vector<MachOObjCViewRow> macho_objc_view_rows(const MachOObjCScan &);
struct MachOObjCTypeImportPlan {
    std::vector<PortableTypeDefinition> definitions;
    std::vector<std::string> skipped;
    std::vector<std::string> conflicts;
};
MachOObjCTypeImportPlan macho_objc_type_import_plan(
    const MachOObjCScan &, const std::vector<database::TypeDefinition> &existing);
wxString macho_objc_view_cell(const MachOObjCViewRow &, int column, const Image *);

} // namespace hexlab::desktop
