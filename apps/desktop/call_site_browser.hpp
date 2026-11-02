#pragma once
#include "hexlab/workspace/project.hpp"
#include <wx/window.h>
#include <optional>

namespace hexlab::desktop {
enum class CallSiteDestination { listing, graph, pseudocode, references, call_evidence, prototype };
struct CallSiteNavigation {
    Address address;
    CallSiteDestination destination;
};
// The caller retains and validates the source document/project after this modal
// chooser returns. Symbolic and unresolved calls never invent a code address.
std::optional<CallSiteNavigation> browse_call_sites(
    wxWindow *, std::shared_ptr<const ProjectSnapshot>, Address selection,
    std::optional<Address> function_entry = {});
} // namespace hexlab::desktop
