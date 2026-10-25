#pragma once

#include "hexlab/workspace/project.hpp"
#include <wx/window.h>
#include <optional>

namespace hexlab::desktop {

struct TypeEditorResult {
    std::string name;
    types::TypePtr type;
};

// Opens the complete project type editor. initial_kind uses the editor's
// stable kind order: integer, boolean, floating, pointer, array, enum,
// function, structure, union.
std::optional<TypeEditorResult> show_type_editor(
    wxWindow *parent, const ProjectSnapshot &project,
    const database::TypeDefinition *original = nullptr,
    int initial_kind = -1);

} // namespace hexlab::desktop
