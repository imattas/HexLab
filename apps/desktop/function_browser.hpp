#pragma once
#include "hexlab/workspace/project.hpp"
#include <wx/window.h>

namespace hexlab::desktop {
enum class FunctionDestination { listing, graph, pseudocode, references, calls };
struct FunctionNavigation {
    Address entry;
    Address address;
    FunctionDestination destination;
};
// The caller must validate the captured document/project before following a result.
std::optional<FunctionNavigation> browse_functions(
    wxWindow *, std::shared_ptr<const ProjectSnapshot>, std::optional<Address> selection);
}
