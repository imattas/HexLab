#pragma once

#include "hexlab/analysis/macho_objc.hpp"
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
};

inline constexpr std::size_t macho_objc_view_row_limit = 250000;

std::vector<MachOObjCViewRow> macho_objc_view_rows(const MachOObjCScan &);
wxString macho_objc_view_cell(const MachOObjCViewRow &, int column, const Image *);

} // namespace hexlab::desktop
