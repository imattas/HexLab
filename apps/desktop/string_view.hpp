#pragma once

#include "data_views.hpp"
#include "hexlab/analysis/references.hpp"
#include <wx/button.h>
#include <wx/splitter.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/timer.h>

namespace hexlab::desktop {

class StringBrowserView final : public wxPanel {
  public:
    explicit StringBrowserView(wxWindow *parent);
    void set_document(std::shared_ptr<const DocumentSnapshot>);
    void select(Location);
    void clear_selection();
    std::function<void(Location)> navigate;

  private:
    static constexpr std::size_t reference_page_size_ = 128;
    std::shared_ptr<const DocumentSnapshot> document_;
    wxTextCtrl *filter_ = nullptr;
    VirtualTable *strings_ = nullptr;
    VirtualTable *references_ = nullptr;
    wxStaticText *reference_summary_ = nullptr;
    wxButton *previous_references_ = nullptr;
    wxButton *next_references_ = nullptr;
    wxTimer filter_timer_;
    std::vector<std::size_t> visible_strings_;
    std::optional<std::size_t> selected_string_;
    std::optional<ReferencePage> reference_page_;
    std::uint64_t reference_offset_ = 0;

    void refresh_strings();
    void refresh_references();
    void choose_string(std::size_t record_index, bool navigate_to_string);
    std::optional<Location> string_location(std::size_t record_index) const;
};

} // namespace hexlab::desktop
