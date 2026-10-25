#pragma once
#include "project_view.hpp"
#include "hexlab/workspace/macho_presentation.hpp"
namespace hexlab::desktop {
wxString macho_symbol_state(MachOSymbolState);
wxString macho_metadata_cell(const DocumentSnapshot &, const MachOMetadataRow &, int column);
} // namespace hexlab::desktop
