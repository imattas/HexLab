#pragma once
#include "hexlab/workspace/listing.hpp"
#include "hexlab/workspace/commands.hpp"
#include "hexlab/processors/format.hpp"
#include <wx/listctrl.h>
#include <wx/panel.h>
#include <wx/stattext.h>
#include <wx/button.h>
#include <functional>
#include <array>

namespace hexlab::desktop {
wxString location_text(Location, const Image * = nullptr);
wxString hex_bytes(std::span<const std::byte>);
wxString text(std::string_view);
class VirtualTable final : public wxListCtrl {
  public:
    VirtualTable(wxWindow *, const wxString &name, std::initializer_list<wxString> columns);
    void populate(std::size_t count, std::function<wxString(std::size_t, int)> cell);
    void select_row(std::size_t row);
    void clear_selection();
    std::optional<std::size_t> selected_row() const;
    // Size from headers and at most64 sampled rows plus the selected row.
    void fit_columns(std::initializer_list<int>, std::optional<std::size_t> selected = {});
    std::function<void(std::size_t)> activate;

  private:
    wxString OnGetItemText(long row, long column) const override;
    std::function<wxString(std::size_t, int)> cell_;
    bool updating_ = false;
};
class ListingView final : public wxPanel {
  public:
    explicit ListingView(wxWindow *);
    void set_document(std::shared_ptr<const DocumentSnapshot>);
    void select(Location);
    void apply_page(Location, const ListingPage &);
    const ListingPage &page() const { return page_; }
    std::function<void(Location)> navigate;
    std::function<void(std::shared_ptr<const DocumentSnapshot>, Location)> request_page;
    std::function<void(Instruction &)> decorate_instruction;
    void refresh_display();

  private:
    VirtualTable *table_;
    wxButton *export_page_ = nullptr;
    ListingPage page_;
    std::shared_ptr<const DocumentSnapshot> document_;
    std::optional<Location> selection_;
    void render();
    void export_page();
};
class BytesView final : public wxPanel {
  public:
    struct TypedRow {
        Location location;
        std::array<wxString, 4> cells;
        std::optional<Address> pointer_target;
    };
    explicit BytesView(wxWindow *);
    void set_document(std::shared_ptr<const DocumentSnapshot>);
    void select(Location);
    std::function<void(Location)> navigate;
    std::function<void(ProjectCommand)> submit;

  private:
    VirtualTable *table_, *typed_table_ = nullptr;
    wxStaticText *typed_status_ = nullptr;
    wxStaticText *firmware_record_status_ = nullptr;
    wxStaticText *patch_help_ = nullptr;
    wxButton *assign_type_ = nullptr, *patch_bytes_ = nullptr, *follow_typed_pointer_ = nullptr;
    wxButton *export_page_ = nullptr;
    wxButton *firmware_record_ = nullptr;
    BytesPage page_{FileOffset{0}, {}, {}};
    std::shared_ptr<const DocumentSnapshot> document_;
    std::optional<Location> selection_;
    std::optional<std::size_t> selected_cell_;
    std::vector<TypedRow> typed_rows_;
    void render();
    void update_patch_availability();
    void update_firmware_record_action();
    void navigate_to_firmware_record();
    void patch_selected_bytes();
    void export_page();
    void refresh_typed_data();
    void update_typed_pointer_action();
    void follow_typed_pointer();
    void apply_type();
};
} // namespace hexlab::desktop
