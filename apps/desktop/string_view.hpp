#pragma once

#include "data_views.hpp"
#include "hexlab/analysis/references.hpp"
#include "hexlab/workspace/document_manager.hpp"
#include <map>
#include <wx/config.h>
#include <wx/button.h>
#include <wx/choice.h>
#include <wx/splitter.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/timer.h>

namespace hexlab::desktop {

class StringBrowserView final : public wxPanel {
  public:
    explicit StringBrowserView(wxWindow *parent);
    void set_document(std::shared_ptr<const DocumentSnapshot>, bool standalone = false);
    void select(Location);
    void clear_selection();
    void synchronize_selection(std::optional<Location>, bool restoring_workspace = false);
    void retain_documents(std::span<const DocumentInfo>);
    void save_preferences(wxConfigBase &, const wxString &group, DocumentId,
                          const ProjectSnapshot &, bool saved_project);
    void restore_preferences(wxConfigBase &, const wxString &group, DocumentId, bool saved_project);
    std::optional<wxString> standalone_comment(Location) const;
    bool set_standalone_comment(Location, const wxString &);
    std::string project_preference_payload(DocumentId,const ProjectSnapshot &);
    void restore_project_preference(std::string_view,DocumentId,const ProjectSnapshot &);
    std::function<void(Location)> navigate;
    std::function<void(Location)> comment;

  private:
    static constexpr std::size_t reference_page_size_ = 128;
    std::shared_ptr<const DocumentSnapshot> document_;
    wxTextCtrl *filter_ = nullptr;
    wxChoice *encoding_ = nullptr;
    wxChoice *mapping_ = nullptr;
    wxChoice *termination_ = nullptr;
    wxChoice *sort_ = nullptr;
    wxTextCtrl *minimum_bytes_ = nullptr;
    wxTextCtrl *maximum_bytes_ = nullptr;
    wxTextCtrl *minimum_characters_ = nullptr;
    wxTextCtrl *maximum_characters_ = nullptr;
    wxStaticText *filter_summary_ = nullptr;
    wxStaticText *cursor_summary_ = nullptr;
    wxButton *reveal_cursor_ = nullptr;
    VirtualTable *strings_ = nullptr;
    VirtualTable *references_ = nullptr;
    wxStaticText *reference_summary_ = nullptr;
    wxButton *export_ = nullptr;
    wxButton *export_all_ = nullptr;
    wxButton *copy_ = nullptr;
    wxButton *comment_ = nullptr;
    wxButton *export_notes_ = nullptr;
    wxButton *import_notes_ = nullptr;
    wxStaticText *action_status_ = nullptr;
    wxTextCtrl *byte_preview_ = nullptr;
    wxButton *copy_byte_preview_ = nullptr;
    wxButton *copy_text_preview_ = nullptr;
    wxButton *copy_json_preview_ = nullptr;
    wxButton *export_bytes_ = nullptr;
    wxButton *previous_references_ = nullptr;
    wxButton *next_references_ = nullptr;
    wxButton *copy_reference_ = nullptr;
    wxButton *copy_reference_page_ = nullptr;
    wxTimer filter_timer_;
    std::vector<std::size_t> visible_strings_;
    std::optional<std::size_t> selected_string_;
    std::optional<ReferencePage> reference_page_;
    std::uint64_t reference_offset_ = 0;
    struct Preferences {
        wxString query, minimum = "0", maximum, minimum_characters = "0", maximum_characters;
        int encoding = -1, mapping = 0, termination = 0, sort = 0;
        std::string identity, selected;
        bool match_project_uuid = true;
        std::optional<Location> context;
        bool context_known = false;
        std::map<std::string, wxString> standalone_comments;
    };
    std::map<std::uint64_t, Preferences> preferences_;
    std::string pending_selection_;
    std::optional<Location> synchronized_context_;
    bool context_known_ = false, preserve_context_once_ = false;
    bool standalone_document_ = false;

    void remember_preferences();
    void restore_standalone_annotations();
    bool persist_standalone_annotations(const Preferences &) const;
    void restore_selected_string();
    wxString comment_for_record(const DocumentSnapshot &, std::size_t) const;

    void refresh_strings();
    void refresh_cursor_context();
    void reset_filters(bool reset_order = true);
    void refresh_references();
    void export_strings(bool filtered);
    void export_standalone_notes();
    void import_standalone_notes();
    void copy_selected_row();
    void copy_byte_preview();
    void copy_text_preview();
    void copy_json_preview();
    void export_selected_bytes();
    void copy_selected_reference();
    void copy_reference_page();
    void refresh_byte_preview();
    void choose_string(std::size_t record_index, bool navigate_to_string);
    std::optional<Location> string_location(std::size_t record_index) const;
};

} // namespace hexlab::desktop
