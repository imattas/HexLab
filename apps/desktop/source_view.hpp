#pragma once

#include "hexlab/workspace/document.hpp"
#include "hexlab/workspace/listing.hpp"
#include <wx/panel.h>
#include <wx/button.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/choice.h>
#include <functional>
#include <optional>
#include <cstdint>
#include <string>
#include <vector>

namespace hexlab::desktop {
class VirtualTable;
class SourceView final : public wxPanel {
  public:
    explicit SourceView(wxWindow *parent);
    void set_document(std::shared_ptr<const DocumentSnapshot> document);
    void select(Location location);

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
    };
    wxTextCtrl *source_ = nullptr;
    wxTextCtrl *source_filter_ = nullptr;
    wxChoice *source_file_ = nullptr;
    wxStaticText *status_ = nullptr;
    std::shared_ptr<const DocumentSnapshot> document_;
    std::vector<SourceRow> rows_;
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
    wxButton *toggle_breakpoint_ = nullptr;
    VirtualTable *mapped_instructions_ = nullptr;
    struct InstructionMapping {
        Address address{};
        wxString instruction;
        wxString state;
    };
    std::vector<InstructionMapping> instruction_mappings_;
    bool updating_ = false;

    void select_source_line();
    void refresh_file_choices(const std::string &preferred_path = {});
    void render_source_row(const SourceRow &, Address context_address);
    void navigate_line_mapping(bool next);
    void render_instruction_mappings(const std::string &path, std::int64_t line, AddressSpaceId space);
    void update_mapping_controls();
    void render_unavailable(const wxString &message);
};
} // namespace hexlab::desktop
