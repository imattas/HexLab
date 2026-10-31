#pragma once
#include "data_views.hpp"
#include "hexlab/workspace/search.hpp"
#include <wx/button.h>
#include <wx/stattext.h>
#include <wx/timer.h>
#include <wx/textctrl.h>
namespace hexlab::desktop {
struct FindRequest {
    SearchQuery query;
    SearchLimits limits;
    bool all_documents = false;
    bool start_from_selection = false;
};
std::optional<FindRequest> find_dialog(wxWindow *);
struct SearchDocumentView {
    DocumentId id;
    wxString label;
    const SearchHistory *history = nullptr;
    bool pending = false;
    wxString reason;
    std::shared_ptr<const Image> image;
    std::shared_ptr<const ProjectSnapshot> project;
};
class SearchView final : public wxPanel {
  public:
    explicit SearchView(wxWindow *);
    ~SearchView() override;
    void update(std::optional<DocumentId>, const SearchHistory *, bool pending, const wxString &reason,
                std::shared_ptr<const Image> = {}, std::shared_ptr<const ProjectSnapshot> = {});
    void update_all(const std::vector<SearchDocumentView> &);
    std::function<void(DocumentId, std::size_t, const SearchMatch &)> navigate;
    std::function<void(DocumentId)> more;
    std::function<void()> more_all;

  private:
    struct Rows;
    struct FilterWork;
    std::shared_ptr<Rows> collection_rows_;
    VirtualTable *table_;
    wxStaticText *status_;
    wxButton *more_;
    wxTextCtrl *filter_, *preview_;
    wxButton *previous_, *next_, *copy_, *export_;
    std::shared_ptr<const Rows> rows_;
    std::shared_ptr<const std::vector<std::size_t>> visible_;
    std::shared_ptr<FilterWork> filter_work_;
    struct CollectionWork;
    std::shared_ptr<CollectionWork> collection_work_;
    wxTimer filter_timer_;
    wxTimer collection_timer_;
    std::optional<DocumentId> selected_document_;
    std::shared_ptr<const SearchPage> selected_page_;
    std::size_t selected_index_ = 0;
    wxString coverage_;
    std::optional<DocumentId> document_;
    std::shared_ptr<const Image> collection_image_;
    std::shared_ptr<const ProjectSnapshot> collection_project_;
    std::optional<std::size_t> history_selected_index_;
    std::vector<std::shared_ptr<const SearchPage>> current_pages_;
    wxString current_reason_;
    bool current_pending_ = false;
    bool all_documents_ = false;
    void render();
    void poll_filter();
    void poll_collection();
    void show_preview();
    void step(bool forward);
    wxString export_text() const;
    void copy_results();
    void export_results();
};
} // namespace hexlab::desktop
