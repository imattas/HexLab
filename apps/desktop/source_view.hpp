#pragma once

#include "hexlab/workspace/document.hpp"
#include "hexlab/workspace/listing.hpp"
#include <wx/panel.h>
#include <wx/button.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/choice.h>
#include <wx/timer.h>
#include <functional>
#include <memory>
#include <optional>
#include <cstdint>
#include <filesystem>
#include <future>
#include <stop_token>
#include <map>
#include <string>
#include <utility>
#include <vector>

class wxCheckBox;
namespace hexlab::desktop {
class VirtualTable;
struct SourceScanCheckpoint;
struct SourceRevisionStamp {
    std::uint64_t document = 0;
    std::uint64_t project_edit = 0, project_bytes = 0, project_decisions = 0;
    bool has_project = false;
    bool operator==(const SourceRevisionStamp &) const = default;
};
struct SourceSearchResult {
    std::string failure;
    bool found = false;
    std::int64_t line = 0;
    std::size_t byte_offset = 0, character_offset = 0;
    std::size_t occurrence = 0, total_occurrences = 0;
};
struct SourceFileLoadResult {
    std::string failure;
    std::string utf8_text;
};
struct SourceRevisionCheckResult {
    std::string status;
};
struct SourceExcerptLoadResult {
    std::string failure;
    std::int64_t first_line = 1;
    std::vector<std::string> lines;
    bool full_file_available = false;
    std::shared_ptr<SourceScanCheckpoint> checkpoint;
};
class SourceView final : public wxPanel {
  public:
    explicit SourceView(wxWindow *parent);
    ~SourceView() override;
    void set_document(std::shared_ptr<const DocumentSnapshot> document);
    void select(Location location);
    bool has_source_mapping(const std::shared_ptr<const DocumentSnapshot> &document, Address address) const;

    std::function<void(Location)> navigate;
    std::function<bool(std::shared_ptr<const DocumentSnapshot>, Address)> toggle_project_breakpoint;

  private:
    struct SourceRow {
        Address address{};
        std::string path;
        std::int64_t line = 0;
        std::uint64_t column = 0;
        std::uint32_t inline_size = 0, inline_depth = 0;
        std::string scope;
        std::optional<std::uint64_t> mapping_end;
    };
    struct SourceRevisionEvidence {
        std::uint8_t checksum_kind = 0;
        std::vector<std::byte> checksum;
        bool conflict = false;
    };
    struct SourceExcerptRequest {
        SourceRow row;
        Address context{};
        std::int64_t focus_line = 0;
        bool continue_scan = false;
        bool resume = false;
        bool page_navigation = false;
        std::shared_ptr<const DocumentSnapshot> document;
        SourceRevisionStamp revision;
        std::shared_ptr<SourceScanCheckpoint> checkpoint;
        std::uint64_t generation = 0;
    };
    struct SourcePendingMatch {
        SourceSearchResult result;
        wxString query;
        std::string path, query_key;
        std::uint64_t generation = 0;
    };
    wxTextCtrl *source_ = nullptr;
    wxTextCtrl *source_filter_ = nullptr;
    wxTextCtrl *source_find_ = nullptr;
    wxCheckBox *source_find_ignore_case_ = nullptr;
    wxChoice *source_file_ = nullptr;
    wxStaticText *status_ = nullptr;
    std::shared_ptr<const DocumentSnapshot> document_;
    struct BrowserState { wxString filter; std::string path; bool ignore_ascii_case = false; };
    std::map<std::uint64_t, BrowserState> browser_states_;
    std::vector<SourceRow> rows_;
    std::map<std::uint32_t, std::vector<std::size_t>> rows_by_space_;
    std::map<std::string, std::vector<std::size_t>> rows_by_path_;
    std::map<std::string, SourceRevisionEvidence> source_revision_evidence_by_path_;
    std::vector<std::optional<Address>> visible_addresses_;
    std::vector<std::int64_t> visible_lines_;
    std::string rendered_path_;
    std::optional<AddressSpaceId> rendered_space_;
    std::optional<Address> selection_address_;
    std::vector<std::string> source_paths_;
    std::vector<std::string> visible_source_paths_;
    std::vector<Address> selected_line_addresses_;
    std::size_t selected_line_address_index_ = 0;
    wxButton *previous_mapping_ = nullptr;
    wxButton *next_mapping_ = nullptr;
    wxButton *previous_match_ = nullptr;
    wxButton *next_match_ = nullptr;
    wxButton *toggle_breakpoint_ = nullptr;
    wxButton *edit_source_ = nullptr;
    wxButton *save_source_ = nullptr;
    wxButton *discard_source_ = nullptr;
    wxButton *continue_source_scan_ = nullptr;
    wxButton *previous_source_page_ = nullptr;
    wxButton *next_source_page_ = nullptr;
    wxButton *load_full_source_ = nullptr;
    wxButton *copy_source_location_ = nullptr;
    wxButton *copy_line_map_ = nullptr;
    wxButton *copy_source_line_ = nullptr;
    wxButton *copy_source_excerpt_ = nullptr;
    wxButton *check_source_revision_ = nullptr;
    VirtualTable *mapped_instructions_ = nullptr;
    struct InstructionMapping {
        Address address{};
        std::uint64_t source_column = 0;
        std::uint32_t inline_depth = 0;
        std::string scope;
        wxString instruction;
        wxString state;
    };
    wxTimer source_search_timer_;
    wxTimer source_load_timer_;
    wxTimer source_excerpt_timer_;
    wxTimer source_revision_timer_;
    std::future<SourceSearchResult> source_search_future_;
    std::stop_source source_search_stop_;
    bool source_search_running_ = false;
    std::future<SourceFileLoadResult> source_load_future_;
    std::stop_source source_load_stop_;
    bool source_load_running_ = false;
    bool source_load_rendering_ = false;
    std::string source_load_render_buffer_;
    std::size_t source_load_render_offset_ = 0;
    std::size_t source_load_next_progress_ = 0;
    std::future<SourceExcerptLoadResult> source_excerpt_future_;
    std::stop_source source_excerpt_stop_;
    bool source_excerpt_running_ = false;
    std::future<SourceRevisionCheckResult> source_revision_future_;
    std::stop_source source_revision_stop_;
    bool source_revision_running_ = false;
    std::shared_ptr<const DocumentSnapshot> source_revision_document_;
    SourceRevisionStamp source_revision_stamp_;
    std::string source_revision_path_;
    std::uint64_t source_revision_generation_ = 0;
    std::uint64_t source_excerpt_generation_ = 0;
    std::optional<SourceExcerptRequest> source_excerpt_active_request_;
    std::optional<SourceExcerptRequest> source_excerpt_queued_request_;
    std::optional<SourcePendingMatch> source_pending_match_;
    bool full_file_display_ = false;
    std::shared_ptr<const DocumentSnapshot> source_load_document_;
    SourceRevisionStamp source_load_stamp_;
    std::string source_load_path_;
    std::optional<Address> source_load_selection_;
    std::shared_ptr<const DocumentSnapshot> source_search_document_;
    SourceRevisionStamp source_search_stamp_;
    std::string source_search_path_, source_search_query_key_;
    wxString source_search_query_;
    bool source_search_ignore_case_ = false;
    std::int64_t source_search_start_line_ = 1;
    std::optional<std::pair<std::int64_t, std::size_t>> source_search_cursor_;
    std::optional<Address> source_search_selection_;
    std::vector<InstructionMapping> instruction_mappings_;
    bool instruction_mappings_truncated_ = false;
    bool updating_ = false;
    bool source_editing_ = false;
    bool source_dirty_ = false;
    bool source_full_file_available_ = false;
    bool source_search_available_ = false;
    bool source_utf8_bom_ = false;
    bool source_utf16_ = false;
    bool source_utf16_little_endian_ = true;
    bool source_default_crlf_ = false;
    std::vector<bool> source_line_endings_crlf_;
    std::filesystem::path editing_path_;
    std::vector<std::byte> original_source_bytes_;
    std::optional<SourceRow> displayed_source_row_;
    Address displayed_context_{};
    std::shared_ptr<SourceScanCheckpoint> source_scan_;
    std::shared_ptr<SourceScanCheckpoint> source_line_index_;
    std::string source_page_path_;
    std::shared_ptr<const DocumentSnapshot> source_scan_document_;
    std::optional<SourceRow> pending_source_row_;
    Address pending_source_context_{};
    std::int64_t pending_source_line_ = 0;
    bool pending_source_page_navigation_ = false;
    std::optional<std::pair<std::int64_t, std::size_t>> source_match_;
    std::string source_match_query_;
    std::string source_match_path_;

    void select_source_line();
    const SourceRow *source_row_for(Address, bool &ambiguous_inline,
                                    const std::string *path = nullptr) const;
    void refresh_file_choices(const std::string &preferred_path = {});
    void render_source_row(const SourceRow &, Address context_address);
    void render_source_row(const SourceRow &, Address context_address, std::int64_t focus_line,
                           bool continue_scan = false, bool page_navigation = false);
    void navigate_line_mapping(bool next);
    void copy_source_location();
    void copy_line_map();
    void copy_source_line();
    void copy_source_excerpt();
    std::optional<std::int64_t> focused_source_line() const;
    void find_source_text(bool next);
    void poll_source_search();
    void load_or_cancel_full_source();
    void poll_full_source_load();
    void start_source_excerpt(SourceExcerptRequest);
    void poll_source_excerpt();
    void check_source_revision();
    void poll_source_revision();
    void apply_source_excerpt(const SourceExcerptRequest &, SourceExcerptLoadResult);
    void apply_source_search_match(const SourceExcerptRequest &);
    void page_source(bool next);
    void render_instruction_mappings(const std::string &path, std::int64_t line, AddressSpaceId space);
    void update_mapping_controls();
    void render_unavailable(const wxString &message);
    bool finish_source_edit();
    void update_source_edit_controls();
    void begin_source_edit();
    void save_source_edit();
    void discard_source_edit();
};
} // namespace hexlab::desktop
