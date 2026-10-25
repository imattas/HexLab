#pragma once
#include "hexlab/workspace/commands.hpp"
#include "hexlab/image/image.hpp"
#include <wx/window.h>
namespace hexlab::desktop {
std::optional<ProjectCommand> reference_dialog(wxWindow*,Location source,AddressSpaceId,
                                              std::shared_ptr<const Image> = {});
}
