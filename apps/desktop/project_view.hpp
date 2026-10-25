#pragma once
#include "data_views.hpp"
#include "hexlab/workspace/project.hpp"
namespace hexlab::desktop {
wxString preview_text(std::string_view,std::size_t limit=512);
wxString analysis_state_text(const ProjectSnapshot&);
bool location_mapped(const ProjectSnapshot&,Location)noexcept;
bool location_patched(const ProjectSnapshot&,Location,std::size_t bytes=1);
wxString listing_text(const DocumentSnapshot&,const ListingRow&,bool full_comment=false);
}
