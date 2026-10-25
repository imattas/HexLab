#pragma once
#include "hexlab/workspace/commands.hpp"
#include <wx/dialog.h>
#include <functional>
namespace hexlab::desktop {
using EditBuilder = std::function<Result<ProjectCommand>(const wxString &)>;
std::optional<ProjectCommand> edit_dialog(wxWindow *, const wxString &title, const wxString &explanation,
                                          const wxString &initial, bool multiline, EditBuilder);
Result<std::vector<std::byte>> parse_patch_text(const wxString &);
Result<std::vector<DecisionRange>> parse_chunk_text(const wxString &, AddressSpaceId);
} // namespace hexlab::desktop
