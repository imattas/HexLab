#include "data_views.hpp"
#include "edit_dialogs.hpp"
#include "project_view.hpp"
#include "hexlab/types/types.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/image/file_publication.hpp"
#include "hexlab/image/file_storage.hpp"
#include <wx/filedlg.h>
#include <wx/panel.h>
#include <wx/sizer.h>
#include <wx/settings.h>
#include <wx/splitter.h>
#include <wx/choicdlg.h>
#include <wx/msgdlg.h>
#include <wx/textctrl.h>
#include <wx/button.h>
#include <bit>
#include <iomanip>
#include <limits>
#include <sstream>
#include <filesystem>
#include <span>
#include <wx/event.h>

namespace hexlab::desktop {
namespace {
constexpr std::size_t desktop_patch_byte_limit = 256;

std::optional<Address> address_for(const Image *image, Location location) {
    if (const auto *address = std::get_if<Address>(&location)) return *address;
    if (!image) return {};
    auto mapped = image->to_address(std::get<FileOffset>(location));
    return mapped ? std::optional<Address>(mapped.value()) : std::nullopt;
}
std::optional<FileOffset> file_for(const Image *image, Location location) {
    if (const auto *file = std::get_if<FileOffset>(&location)) return *file;
    if (!image) return {};
    auto mapped = image->to_file_offset(std::get<Address>(location));
    return mapped ? std::optional<FileOffset>(mapped.value()) : std::nullopt;
}
bool location_in_range(Location begin, std::size_t size, Location selected, const Image *image) {
    if (!size) return false;
    if (const auto *address = std::get_if<Address>(&begin)) {
        auto target = address_for(image, selected);
        return target && target->space == address->space && target->offset >= address->offset &&
               target->offset - address->offset < size;
    }
    auto target = file_for(image, selected);
    const auto start = std::get<FileOffset>(begin).value;
    return target && target->value >= start && target->value - start < size;
}
std::optional<Location> containing_instruction_start(const DocumentSnapshot &document, Location location) {
    const auto address = address_for(document.image.get(), location);
    if (!address) return {};
    const std::vector<Instruction> *analysis_instructions = nullptr;
    const std::vector<std::shared_ptr<const InstructionFact>> *project_instructions = nullptr;
    if (document.project && document.project->state && document.project->functions && document.project->functions->key &&
        document.project->functions->key->byte_revision == document.project->state->revisions.bytes &&
        document.project->functions->key->decision_revision == document.project->state->revisions.decisions)
        project_instructions = &document.project->functions->instructions;
    else if (!document.project && document.analysis)
        analysis_instructions = &document.analysis->instructions;

    if (project_instructions) {
        auto found = std::upper_bound(project_instructions->begin(), project_instructions->end(), *address,
            [](Address at, const auto &fact) {
                const auto start = fact->instruction.address;
                return start.space.value < at.space.value ||
                       (start.space == at.space && start.offset < at.offset);
            });
        if (found != project_instructions->begin()) {
            const auto &instruction = (*std::prev(found))->instruction;
            if (instruction.address.space == address->space && address->offset >= instruction.address.offset &&
                address->offset - instruction.address.offset < std::max<std::uint32_t>(1, instruction.byte_length()))
                return Location{instruction.address};
        }
    } else if (analysis_instructions) {
        auto found = std::upper_bound(analysis_instructions->begin(), analysis_instructions->end(), *address,
            [](Address at, const Instruction &instruction) {
                const auto start = instruction.address;
                return start.space.value < at.space.value ||
                       (start.space == at.space && start.offset < at.offset);
            });
        if (found != analysis_instructions->begin()) {
            const auto &instruction = *std::prev(found);
            if (instruction.address.space == address->space && address->offset >= instruction.address.offset &&
                address->offset - instruction.address.offset < std::max<std::uint32_t>(1, instruction.byte_length()))
                return Location{instruction.address};
        }
    }
    return {};
}
Location byte_location(const ByteCell &cell) {
    return cell.address ? Location{*cell.address} : Location{*cell.file_offset};
}
bool cell_matches(const ByteCell &cell, Location location, const Image *image) {
    if (const auto *address = std::get_if<Address>(&location)) {
        if (cell.address && *cell.address == *address) return true;
        auto mapped = file_for(image, location);
        return mapped && cell.file_offset && *cell.file_offset == *mapped;
    }
    const auto file = std::get<FileOffset>(location);
    if (cell.file_offset && *cell.file_offset == file) return true;
    auto mapped = address_for(image, location);
    return mapped && cell.address && *cell.address == *mapped;
}
constexpr std::size_t typed_preview_byte_limit = 64 * 1024;
constexpr std::size_t typed_preview_row_limit = 512;
constexpr std::uint64_t typed_preview_array_limit = 128;
constexpr unsigned typed_preview_depth_limit = 6;

std::uint64_t decode_unsigned(std::span<const std::byte> bytes, ByteOrder order) {
    std::uint64_t value = 0;
    if (order == ByteOrder::little) {
        for (std::size_t i = 0; i < bytes.size(); ++i)
            value |= std::uint64_t(std::to_integer<std::uint8_t>(bytes[i])) << (i * 8);
    } else {
        for (const auto byte : bytes)
            value = (value << 8) | std::to_integer<std::uint8_t>(byte);
    }
    return value;
}

std::string scalar_value(const types::Type &type, std::span<const std::byte> bytes, ByteOrder order) {
    const auto kind = type.kind();
    if (kind == types::Kind::floating) {
        const auto bits = decode_unsigned(bytes, order);
        std::ostringstream out;
        out << std::setprecision(9);
        if (bytes.size() == 4)
            out << std::bit_cast<float>(static_cast<std::uint32_t>(bits));
        else if (bytes.size() == 8)
            out << std::setprecision(17) << std::bit_cast<double>(bits);
        else
            return "unsupported float width (" + std::to_string(bytes.size()) + " bytes)";
        return out.str();
    }
    if (kind != types::Kind::boolean && kind != types::Kind::integer && kind != types::Kind::pointer &&
        kind != types::Kind::enumeration) {
        auto display = hex_bytes(bytes);
        auto utf8 = display.utf8_str();
        return "opaque bytes: " + std::string(utf8.data(), utf8.length());
    }
    if (bytes.empty() || bytes.size() > 8)
        return "unsupported scalar width (" + std::to_string(bytes.size()) + " bytes)";
    const auto value = decode_unsigned(bytes, order);
    if (kind == types::Kind::boolean)
        return value ? "true" : "false";
    if (kind == types::Kind::pointer) {
        std::ostringstream out;
        out << "0x" << std::hex << std::uppercase << value << " (not dereferenced)";
        return out.str();
    }
    if (kind == types::Kind::enumeration) {
        for (const auto &item : type.enumerator_values())
            if (item.value == value)
                return item.name + " (" + std::to_string(value) + ")";
    }
    if (kind == types::Kind::integer && type.is_signed()) {
        std::int64_t signed_value;
        if (bytes.size() == 8) {
            signed_value = std::bit_cast<std::int64_t>(value);
        } else {
            const auto bits = static_cast<unsigned>(bytes.size() * 8);
            const auto sign = std::uint64_t{1} << (bits - 1);
            signed_value = static_cast<std::int64_t>((value ^ sign) - sign);
        }
        return std::to_string(signed_value);
    }
    std::ostringstream out;
    out << value << " (0x" << std::hex << std::uppercase << value << ')';
    return out.str();
}

void collect_typed_rows(const types::Type &type, std::string path, std::uint64_t offset,
                        std::span<const std::byte> bytes, Address base, ByteOrder order,
                        unsigned depth, std::vector<BytesView::TypedRow> &rows) {
    if (rows.size() >= typed_preview_row_limit)
        return;
    if (depth > typed_preview_depth_limit) {
        rows.push_back({Location{base}, {wxString::Format("+0x%llX", static_cast<unsigned long long>(offset)),
                                         text(path), text(types::format(type)), "nesting limit"}});
        return;
    }
    if (type.kind() == types::Kind::qualified && type.element()) {
        collect_typed_rows(*type.element(), std::move(path), offset, bytes, base, order, depth + 1, rows);
        return;
    }
    if (type.kind() == types::Kind::structure || type.kind() == types::Kind::union_type) {
        bool emitted = false;
        for (std::size_t index = 0; index < type.members().size() && rows.size() < typed_preview_row_limit; ++index) {
            const auto &member = type.members()[index];
            const auto member_name = member.name.empty() ? ("member_" + std::to_string(index)) : member.name;
            if (member.virtual_base || !member.type || !member.type->size()) {
                rows.push_back({Location{base}, {wxString::Format("+0x%llX", static_cast<unsigned long long>(offset)),
                    text(path + "." + member_name), member.type ? text(types::format(*member.type)) : wxString("<no type>"),
                    member.virtual_base ? "runtime virtual base" : "incomplete member type"}});
                emitted = true;
                continue;
            }
            if (offset > bytes.size() || member.offset > bytes.size() - offset ||
                *member.type->size() > bytes.size() - (offset + member.offset))
                continue;
            collect_typed_rows(*member.type, path.empty() ? member_name : path + "." + member_name,
                               offset + member.offset, bytes, base, order, depth + 1, rows);
            emitted = true;
        }
        if (!emitted)
            rows.push_back({Location{base}, {wxString::Format("+0x%llX", static_cast<unsigned long long>(offset)),
                text(path), text(types::format(type)), "no fixed-size data members"}});
        return;
    }
    if (type.kind() == types::Kind::array && type.element()) {
        if (type.count() == 0) {
            rows.push_back({Location{base}, {wxString::Format("+0x%llX", static_cast<unsigned long long>(offset)),
                text(path), text(types::format(type)), "incomplete array"}});
            return;
        }
        const auto element_size = type.element()->size();
        if (!element_size || !*element_size) {
            rows.push_back({Location{base}, {wxString::Format("+0x%llX", static_cast<unsigned long long>(offset)),
                text(path), text(types::format(type)), "array element has no fixed size"}});
            return;
        }
        const auto count = std::min(type.count(), typed_preview_array_limit);
        std::uint64_t emitted = 0;
        for (; emitted < count && rows.size() < typed_preview_row_limit; ++emitted) {
            const auto relative = emitted * *element_size;
            if (offset > bytes.size() || relative > bytes.size() - offset ||
                *element_size > bytes.size() - (offset + relative))
                break;
            collect_typed_rows(*type.element(), path + "[" + std::to_string(emitted) + "]",
                               offset + relative, bytes, base, order, depth + 1, rows);
        }
        if (type.count() > emitted && rows.size() < typed_preview_row_limit)
            rows.push_back({Location{base}, {wxString::Format("+0x%llX", static_cast<unsigned long long>(offset)),
                text(path), text(types::format(type)), "elements omitted by preview bound"}});
        return;
    }
    const auto size = type.size();
    if (!size || !*size || offset > bytes.size() || *size > bytes.size() - offset) {
        rows.push_back({Location{base}, {wxString::Format("+0x%llX", static_cast<unsigned long long>(offset)),
            text(path), text(types::format(type)), "unavailable or out-of-range"}});
        return;
    }
    auto location = advance(base, offset);
    if (!location)
        return;
    rows.push_back({Location{location.value()}, {wxString::Format("+0x%llX", static_cast<unsigned long long>(offset)),
        text(path), text(types::format(type)), text(scalar_value(type, bytes.subspan(static_cast<std::size_t>(offset),
                                             static_cast<std::size_t>(*size)), order))}});
}
}
wxString text(std::string_view value) { return wxString::FromUTF8(value.data(), value.size()); }
wxString location_text(Location location, const Image *image) { return text(format_location(location, image)); }
wxString hex_bytes(std::span<const std::byte> bytes) {
    wxString result;
    for (auto b : bytes) {
        if (!result.empty())
            result += ' ';
        result += wxString::Format("%02X", std::to_integer<unsigned>(b));
    }
    return result;
}
VirtualTable::VirtualTable(wxWindow *parent, const wxString &name, std::initializer_list<wxString> columns)
    : wxListCtrl(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_REPORT | wxLC_VIRTUAL | wxLC_SINGLE_SEL) {
    SetName(name);
    SetToolTip("Use the arrow keys and Page Up/Page Down to move through rows. Press Enter or double-click to activate the selected row.");
    SetFont(wxSystemSettings::GetFont(wxSYS_ANSI_FIXED_FONT));
    int index = 0;
    for (const auto &column : columns)
        InsertColumn(index++, column, wxLIST_FORMAT_LEFT, FromDIP(column == "Text" ? 300 : 180));
    auto selected = [this](wxListEvent &event) {
        if (!updating_ && event.GetIndex() >= 0 && event.GetIndex() < GetItemCount() && activate)
            activate(static_cast<std::size_t>(event.GetIndex()));
    };
    Bind(wxEVT_LIST_ITEM_SELECTED, selected);
    Bind(wxEVT_LIST_ITEM_ACTIVATED, selected);
}
void VirtualTable::populate(std::size_t count, std::function<wxString(std::size_t, int)> cell) {
    // Native selection notifications can request old rows while the model is
    // being replaced. Suspend the renderer before touching native list state.
    updating_ = true;
    cell_ = {};
    SetItemState(-1, 0, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
    SetItemCount(static_cast<long>(std::min(count, static_cast<std::size_t>(std::numeric_limits<long>::max()))));
    cell_ = std::move(cell);
    updating_ = false;
    Refresh();
}
void VirtualTable::select_row(std::size_t row) {
    if (row >= static_cast<std::size_t>(GetItemCount()))
        return;
    updating_ = true;
    SetItemState(-1, 0, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
    const auto index = static_cast<long>(row);
    SetItemState(index, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
    EnsureVisible(index);
    updating_ = false;
}
void VirtualTable::clear_selection() {
    updating_ = true;
    SetItemState(-1, 0, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
    updating_ = false;
}
std::optional<std::size_t> VirtualTable::selected_row() const {
    const auto row = GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0)
        return {};
    return static_cast<std::size_t>(row);
}
void VirtualTable::fit_columns(std::initializer_list<int> columns, std::optional<std::size_t> selected) {
    const auto count = static_cast<std::size_t>(GetItemCount());
    const auto first = std::min<std::size_t>(count, 32);
    const auto tail = std::max(first, count > 32 ? count - 32 : 0);
    for (const auto column : columns) {
        wxListItem header;
        header.SetMask(wxLIST_MASK_TEXT);
        if (column < 0 || !GetColumn(column, header))
            continue;
        auto width = GetTextExtent(header.GetText()).x;
        const auto measure = [&](std::size_t row) {
            if (cell_)
                width = std::max(width, GetTextExtent(cell_(row, column)).x);
        };
        for (std::size_t n = 0; n < first; ++n)
            measure(n);
        for (auto n = tail; n < count; ++n)
            measure(n);
        if (selected && *selected < count && *selected >= first && *selected < tail)
            measure(*selected);
        width = std::clamp(width + FromDIP(18), FromDIP(60), FromDIP(360));
        if (GetColumnWidth(column) != width)
            SetColumnWidth(column, width);
    }
}
wxString VirtualTable::OnGetItemText(long row, long column) const {
    return cell_ && row >= 0 && row < GetItemCount() ? cell_(static_cast<std::size_t>(row), static_cast<int>(column))
                                                     : wxString{};
}
ListingView::ListingView(wxWindow *parent) : wxPanel(parent) {
    table_ = new VirtualTable(this, "disassembly", {"Address / offset", "Bytes", "Text", "Analysis"});
    const int widths[] = {140, 100, 320, 160};
    for (int i = 0; i < 4; ++i)
        table_->SetColumnWidth(i, FromDIP(widths[i]));
    auto *sizer = new wxBoxSizer(wxVERTICAL);
    auto *toolbar = new wxBoxSizer(wxHORIZONTAL);
    toolbar->AddStretchSpacer();
    export_page_ = new wxButton(this, wxID_ANY, "Export page as TSV...");
    export_page_->SetName("disassembly-export-page");
    export_page_->Disable();
    export_page_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { export_page(); });
    toolbar->Add(export_page_, 0, wxALL, FromDIP(3));
    sizer->Add(toolbar, 0, wxEXPAND);
    sizer->Add(table_, 1, wxEXPAND);
    SetSizer(sizer);
    table_->activate = [this](std::size_t row) {
        if (row < page_.rows.size() && navigate)
            navigate(page_.rows[row].location);
    };
}
void ListingView::set_document(std::shared_ptr<const DocumentSnapshot> doc) {
    document_ = std::move(doc);
    page_ = {};
    selection_.reset();
    table_->populate(0, {});
    export_page_->Disable();
}
void ListingView::select(Location location) {
    selection_ = location;
    for (std::size_t row = 0; row < page_.rows.size(); ++row)
        if (page_.rows[row].location == location ||
            location_in_range(page_.rows[row].location,
                page_.rows[row].instruction ? std::max<std::uint32_t>(1, page_.rows[row].instruction->byte_length()) : page_.rows[row].bytes.size(),
                location, document_ && document_->image ? document_->image.get() : nullptr)) {
            table_->select_row(row);
            if (page_.rows[row].location == location && document_ && document_->project && !page_.rows[row].instruction &&
                std::holds_alternative<Address>(location) && request_page)
                request_page(document_, location);
            return;
        }
    if (!document_)
        return;
    const auto page_begin = containing_instruction_start(*document_, location).value_or(location);
    auto result = make_listing_page(*document_, page_begin, 256, ListingOptions{!document_->project, {}});
    page_ = result ? std::move(result.value()) : ListingPage{};
    render();
    if (document_->project && std::holds_alternative<Address>(location) && !page_.rows.empty() &&
        !page_.rows.front().instruction && request_page)
        request_page(document_, location);
}
void ListingView::apply_page(Location location, const ListingPage &page) {
    page_ = page;
    render();
    for (std::size_t row = 0; row < page_.rows.size(); ++row)
        if (page_.rows[row].location == location) {
            table_->select_row(row);
            break;
        }
}
void ListingView::refresh_display() { render(); }
void ListingView::render() {
    table_->populate(page_.rows.size(), [this](std::size_t row, int column) {
        if (row >= page_.rows.size())
            return wxString{};
        const auto &item = page_.rows[row];
        switch (column) {
        case 0:
            return location_text(item.location, document_ ? document_->image.get() : nullptr);
        case 1:
            return hex_bytes(item.bytes);
        case 2:
            if (!document_) return wxString{};
            if (!item.instruction || !decorate_instruction) return listing_text(*document_, item);
            else {
                auto decorated = item;
                decorate_instruction(*decorated.instruction);
                return listing_text(*document_, decorated);
            }
        default: {
            auto value = text(item.status);
            if (document_ && document_->project) {
                if (location_patched(*document_->project, item.location, item.bytes.size()))
                    value += "; patched";
                if (document_->project->status != DerivedStatus::fresh)
                    value += "; " + analysis_state_text(*document_->project);
            }
            return value;
        }
        }
    });
    export_page_->Enable(document_ && !page_.rows.empty());
    if (!page_.rows.empty()) {
        for (std::size_t row = 0; row < page_.rows.size(); ++row) {
            const auto &item = page_.rows[row];
            const auto length = item.instruction ? std::max<std::uint32_t>(1, item.instruction->byte_length()) : item.bytes.size();
            if (selection_ && (item.location == *selection_ ||
                location_in_range(item.location, length, *selection_, document_ && document_->image ? document_->image.get() : nullptr))) {
                table_->select_row(row);
                return;
            }
        }
        table_->select_row(0);
    }
}
void ListingView::export_page() {
    if (!document_ || page_.rows.empty())
        return;

    // Capture rows before the modal picker can process other UI events.
    const auto document = document_;
    const auto page = page_;
    std::string output = "Address / offset\tBytes\tText\tAnalysis\n";
    const auto append_field = [&](const wxString &value) {
        const auto encoded = value.utf8_str();
        for (std::size_t index = 0; index < encoded.length(); ++index) {
            const char byte = encoded.data()[index];
            switch (byte) {
            case '\\': output += "\\\\"; break;
            case '\t': output += "\\t"; break;
            case '\r': output += "\\r"; break;
            case '\n': output += "\\n"; break;
            default: output.push_back(byte); break;
            }
        }
    };
    for (const auto &row : page.rows) {
        append_field(location_text(row.location, document->image.get()));
        output.push_back('\t');
        append_field(hex_bytes(row.bytes));
        output.push_back('\t');
        if (row.instruction && decorate_instruction) {
            auto decorated = row;
            decorate_instruction(*decorated.instruction);
            append_field(listing_text(*document, decorated, true));
        } else {
            append_field(listing_text(*document, row, true));
        }
        output.push_back('\t');
        wxString analysis = text(row.status);
        if (document->project) {
            if (location_patched(*document->project, row.location, row.bytes.size()))
                analysis += "; patched";
            if (document->project->status != DerivedStatus::fresh)
                analysis += "; " + analysis_state_text(*document->project);
        }
        append_field(analysis);
        output.push_back('\n');
    }

    auto protected_paths = document->project ? document->project->protected_paths
                                              : std::vector<std::filesystem::path>{};
    if (const auto file = std::dynamic_pointer_cast<const FileStorage>(document->input_storage))
        protected_paths.push_back(file->backing_path());
    wxFileDialog dialog(this, "Export visible disassembly", "", "disassembly-page.tsv",
                        "TSV files (*.tsv)|*.tsv|All files (*.*)|*.*", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (dialog.ShowModal() != wxID_OK)
        return;
    auto publication = FilePublication::create(std::filesystem::path(dialog.GetPath().ToStdWstring()),
                                               ExistingFilePolicy::replace, protected_paths, {});
    if (!publication) {
        wxMessageBox(text(publication.error().message), "Export disassembly", wxOK | wxICON_ERROR, this);
        return;
    }
    const auto written = publication.value()->append(std::as_bytes(std::span(output.data(), output.size())));
    if (!written) {
        wxMessageBox(text(written.error().message), "Export disassembly", wxOK | wxICON_ERROR, this);
        return;
    }
    const auto published = publication.value()->publish();
    if (!published)
        wxMessageBox(text(published.error().message), "Export disassembly", wxOK | wxICON_ERROR, this);
}
BytesView::BytesView(wxWindow *parent) : wxPanel(parent) {
    auto *splitter = new wxSplitterWindow(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                          wxSP_LIVE_UPDATE | wxSP_3D);
    table_ = new VirtualTable(splitter, "bytes", {"Address / offset", "Hex bytes", "Text", "Backing"});
    const int widths[] = {140, 210, 90, 140};
    for (int i = 0; i < 4; ++i)
        table_->SetColumnWidth(i, FromDIP(widths[i]));
    auto *typed_panel = new wxPanel(splitter);
    auto *typed_sizer = new wxBoxSizer(wxVERTICAL);
    auto *typed_header = new wxBoxSizer(wxHORIZONTAL);
    typed_status_ = new wxStaticText(typed_panel, wxID_ANY,
        "Assign a project type at the selected address to inspect its fields and array elements.");
    typed_status_->SetName("typed-data-status");
    typed_header->Add(typed_status_, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(8));
    patch_bytes_ = new wxButton(typed_panel, wxID_ANY, "Patch bytes...");
    patch_bytes_->SetName("bytes-patch");
    patch_bytes_->Disable();
    typed_header->Add(patch_bytes_, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    assign_type_ = new wxButton(typed_panel, wxID_ANY, "Assign type at cursor...");
    assign_type_->SetName("typed-data-assign");
    assign_type_->Disable();
    typed_header->Add(assign_type_, 0, wxALIGN_CENTER_VERTICAL);
    typed_sizer->Add(typed_header, 0, wxEXPAND | wxALL, FromDIP(4));
    patch_help_ = new wxStaticText(typed_panel, wxID_ANY,
        "Patches are one undoable project step. Byte-dependent analysis refreshes for the new byte revision.");
    patch_help_->SetName("bytes-patch-help");
    patch_help_->Wrap(FromDIP(700));
    typed_sizer->Add(patch_help_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    typed_table_ = new VirtualTable(typed_panel, "typed-data-members", {"Offset", "Member / element", "Type", "Value"});
    const int typed_widths[] = {90, 210, 240, 260};
    for (int i = 0; i < 4; ++i)
        typed_table_->SetColumnWidth(i, FromDIP(typed_widths[i]));
    typed_sizer->Add(typed_table_, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    typed_panel->SetSizer(typed_sizer);
    splitter->SetMinimumPaneSize(FromDIP(90));
    splitter->SplitHorizontally(table_, typed_panel, FromDIP(380));
    auto *sizer = new wxBoxSizer(wxVERTICAL);
    sizer->Add(splitter, 1, wxEXPAND);
    SetSizer(sizer);
    table_->activate = [this](std::size_t row) {
        auto i = row * 8;
        if (i < page_.cells.size() && navigate) {
            const auto &cell = page_.cells[i];
            selected_cell_ = i;
            navigate(byte_location(cell));
        }
    };
    table_->Bind(wxEVT_CHAR_HOOK, [this](wxKeyEvent &event) {
        if ((event.GetKeyCode() != WXK_LEFT && event.GetKeyCode() != WXK_RIGHT) || page_.cells.empty()) {
            event.Skip();
            return;
        }
        const auto current = selected_cell_.value_or(0);
        std::size_t next = current;
        if (event.GetKeyCode() == WXK_LEFT) {
            if (current == 0) return;
            next = current - 1;
        } else {
            if (current + 1 >= page_.cells.size()) {
                if (page_.next && navigate) navigate(*page_.next);
                return;
            }
            next = current + 1;
        }
        selected_cell_ = next;
        table_->select_row(next / 8);
        if (navigate) navigate(byte_location(page_.cells[next]));
    });
    typed_table_->activate = [this](std::size_t row) {
        if (row < typed_rows_.size() && navigate)
            navigate(typed_rows_[row].location);
    };
    assign_type_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { apply_type(); });
    patch_bytes_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { patch_selected_bytes(); });
}
void BytesView::set_document(std::shared_ptr<const DocumentSnapshot> doc) {
    document_ = std::move(doc);
    page_.cells.clear();
    selection_.reset();
    selected_cell_.reset();
    table_->populate(0, {});
    update_patch_availability();
    refresh_typed_data();
}
void BytesView::select(Location location) {
    if (!document_)
        return;
    selection_ = location;
    std::optional<std::size_t> index;
    for (std::size_t i = 0; i < page_.cells.size(); ++i)
        if (cell_matches(page_.cells[i], location, document_->image.get())) { index = i; break; }
    if (!index) {
        auto result = make_bytes_page(*document_, location);
        page_ = result ? std::move(result.value()) : BytesPage{location, {}, {}};
        index = page_.cells.empty() ? std::nullopt : std::optional<std::size_t>(0);
    }
    selected_cell_ = index;
    render();
}
void BytesView::render() {
    table_->populate((page_.cells.size() + 7) / 8, [this](std::size_t row, int column) {
        const auto first = row * 8;
        if (first >= page_.cells.size())
            return wxString{};
        const auto &start = page_.cells[first];
        if (column == 0)
            return location_text(start.address ? Location{*start.address} : Location{*start.file_offset},
                                 document_->image.get());
        wxString value;
        bool initialized = true;
        for (auto i = first; i < std::min(first + 8, page_.cells.size()); ++i) {
            const auto &cell = page_.cells[i];
            initialized &= cell.initialized;
            if (column == 1) {
                if (i != first)
                    value += ' ';
                const auto byte = wxString::Format("%02X", std::to_integer<unsigned>(cell.value));
                value += selected_cell_ && *selected_cell_ == i ? wxString("[") + byte + "]" : byte;
            }
            if (column == 2) {
                auto b = std::to_integer<unsigned>(cell.value);
                value += wxUniChar(b >= 32 && b < 127 ? b : '.');
            }
        }
        if (column == 3) {
            auto result = initialized ? wxString("file-backed") : wxString("includes zero fill");
            auto location = byte_location(start);
            if (document_->project &&
                location_patched(*document_->project, location, std::min<std::size_t>(8, page_.cells.size() - first)))
                result += "; patched";
            return result;
        }
        return value;
    });
    if (selected_cell_ && *selected_cell_ < page_.cells.size())
        table_->select_row(*selected_cell_ / 8);
    update_patch_availability();
    refresh_typed_data();
}
void BytesView::update_patch_availability() {
    if (!patch_bytes_)
        return;
    const auto project = document_ ? document_->project : nullptr;
    const auto cell = selected_cell_ && *selected_cell_ < page_.cells.size()
        ? std::optional<ByteCell>(page_.cells[*selected_cell_]) : std::nullopt;
    patch_bytes_->Enable(project && project->state && project->mode == database::ProjectMode::read_write && submit &&
                         cell && cell->initialized && cell->file_offset.has_value());
}

void BytesView::patch_selected_bytes() {
    const auto project = document_ ? document_->project : nullptr;
    if (!document_ || !document_->image || !project || !project->state ||
        project->mode != database::ProjectMode::read_write || !submit || !selected_cell_ ||
        *selected_cell_ >= page_.cells.size())
        return;

    const auto start = byte_location(page_.cells[*selected_cell_]);
    auto preview_page = make_bytes_page(*document_, start, desktop_patch_byte_limit);
    if (!preview_page || preview_page.value().cells.empty()) {
        const auto message = preview_page ? "The selected address has no patchable bytes."
                                          : preview_page.error().message;
        wxMessageBox(text(message), "Patch bytes", wxOK | wxICON_WARNING, this);
        return;
    }
    const auto &cells = preview_page.value().cells;
    if (!cells.front().file_offset || !cells.front().initialized) {
        wxMessageBox("The selected byte is not backed by initialized file data.", "Patch bytes",
                     wxOK | wxICON_WARNING, this);
        return;
    }
    const auto file_begin = cells.front().file_offset->value;
    const auto selected_address = std::get_if<Address>(&start);

    const auto range_is_patchable = [&](std::size_t count) {
        if (!count || count > desktop_patch_byte_limit || count > cells.size())
            return false;
        for (std::size_t i = 0; i < count; ++i) {
            const auto &cell = cells[i];
            if (!cell.initialized || !cell.file_offset ||
                cell.file_offset->value < file_begin || cell.file_offset->value - file_begin != i)
                return false;
            if (selected_address) {
                if (!cell.address || cell.address->space != selected_address->space ||
                    cell.address->offset < selected_address->offset ||
                    cell.address->offset - selected_address->offset != i)
                    return false;
            }
        }
        return true;
    };

    if (!range_is_patchable(1)) {
        wxMessageBox("The selected address is not a contiguous, initialized, file-backed range.", "Patch bytes",
                     wxOK | wxICON_WARNING, this);
        return;
    }

    const auto initial_count = std::min<std::size_t>(8, cells.size());
    if (!range_is_patchable(initial_count)) {
        wxMessageBox("The preview range crosses a mapping gap or uninitialized bytes.", "Patch bytes",
                     wxOK | wxICON_WARNING, this);
        return;
    }
    std::vector<std::byte> initial_bytes;
    initial_bytes.reserve(initial_count);
    for (std::size_t i = 0; i < initial_count; ++i)
        initial_bytes.push_back(cells[i].value);

    wxDialog dialog(this, wxID_ANY, "Patch bytes", wxDefaultPosition, wxDefaultSize,
                    wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
    auto *layout = new wxBoxSizer(wxVERTICAL);
    const auto target_text = location_text(start, document_->image.get());
    auto *target = new wxStaticText(&dialog, wxID_ANY,
        "Target: " + target_text + "\nEnter 1 to 256 replacement octets. The range must stay contiguous and file-backed.");
    target->SetName("bytes-patch-target");
    target->Wrap(dialog.FromDIP(660));
    layout->Add(target, 0, wxEXPAND | wxALL, dialog.FromDIP(8));
    auto *replacement_label = new wxStaticText(&dialog, wxID_ANY, "Replacement hex octets:");
    layout->Add(replacement_label, 0, wxLEFT | wxRIGHT | wxTOP, dialog.FromDIP(8));
    auto *replacement = new wxTextCtrl(&dialog, wxID_ANY, hex_bytes(initial_bytes), wxDefaultPosition,
                                       dialog.FromDIP(wxSize(620, 34)), wxTE_PROCESS_ENTER);
    replacement->SetName("bytes-patch-replacement");
    replacement->SetMaxLength(static_cast<unsigned long>(desktop_patch_byte_limit * 3));
    replacement->SetHint("90 90 90");
    layout->Add(replacement, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, dialog.FromDIP(8));
    auto *current_preview = new wxStaticText(&dialog, wxID_ANY, "Current: ");
    current_preview->SetName("bytes-patch-current-preview");
    auto *new_preview = new wxStaticText(&dialog, wxID_ANY, "Replacement: ");
    new_preview->SetName("bytes-patch-new-preview");
    auto *status = new wxStaticText(&dialog, wxID_ANY, "");
    status->SetName("bytes-patch-validation");
    layout->Add(current_preview, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, dialog.FromDIP(8));
    layout->Add(new_preview, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, dialog.FromDIP(8));
    layout->Add(status, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, dialog.FromDIP(8));
    auto *buttons = new wxStdDialogButtonSizer();
    auto *apply = new wxButton(&dialog, wxID_OK, "Apply patch");
    auto *cancel = new wxButton(&dialog, wxID_CANCEL, "Cancel");
    apply->SetName("bytes-patch-apply");
    cancel->SetName("bytes-patch-cancel");
    apply->Disable();
    buttons->AddButton(apply);
    buttons->AddButton(cancel);
    buttons->Realize();
    layout->Add(buttons, 0, wxEXPAND | wxALL, dialog.FromDIP(8));
    dialog.SetSizerAndFit(layout);
    dialog.SetMinSize(dialog.FromDIP(wxSize(600, 210)));

    std::optional<ProjectCommand> command;
    const auto refresh_preview = [&] {
        apply->Disable();
        auto parsed = parse_patch_text(replacement->GetValue());
        if (!parsed) {
            current_preview->SetLabel("Current: —");
            new_preview->SetLabel("Replacement: —");
            status->SetLabel(text(parsed.error().message));
        } else if (parsed.value().empty() || parsed.value().size() > desktop_patch_byte_limit) {
            current_preview->SetLabel("Current: —");
            new_preview->SetLabel("Replacement: —");
            status->SetLabel("Enter 1 to 256 octets.");
        } else if (!range_is_patchable(parsed.value().size())) {
            current_preview->SetLabel("Current: —");
            new_preview->SetLabel("Replacement: " + hex_bytes(parsed.value()));
            status->SetLabel("The replacement crosses an unmapped, uninitialized, or non-contiguous range.");
        } else {
            std::vector<std::byte> current;
            current.reserve(parsed.value().size());
            for (std::size_t i = 0; i < parsed.value().size(); ++i)
                current.push_back(cells[i].value);
            current_preview->SetLabel("Current (" + wxString::Format("%zu", current.size()) +
                                      " bytes): " + hex_bytes(current));
            new_preview->SetLabel("Replacement (" + wxString::Format("%zu", parsed.value().size()) +
                                  " bytes): " + hex_bytes(parsed.value()));
            if (current == parsed.value())
                status->SetLabel("No byte changes to apply.");
            else {
                status->SetLabel("Ready. Apply creates one undoable project history step; affected analysis is "
                                 "invalidated and refreshed for the new byte revision.");
                apply->Enable();
            }
        }
        current_preview->Wrap(dialog.FromDIP(660));
        new_preview->Wrap(dialog.FromDIP(660));
        status->Wrap(dialog.FromDIP(660));
        dialog.Layout();
        dialog.Fit();
    };
    replacement->Bind(wxEVT_TEXT, [&](wxCommandEvent &) { refresh_preview(); });
    replacement->Bind(wxEVT_TEXT_ENTER, [&](wxCommandEvent &) {
        if (apply->IsEnabled()) {
            auto parsed = parse_patch_text(replacement->GetValue());
            if (parsed && range_is_patchable(parsed.value().size())) {
                command = PatchBytes{start, std::move(parsed.value())};
                dialog.EndModal(wxID_OK);
            }
        }
    });
    apply->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) {
        auto parsed = parse_patch_text(replacement->GetValue());
        if (!parsed || parsed.value().empty() || parsed.value().size() > desktop_patch_byte_limit ||
            !range_is_patchable(parsed.value().size())) {
            refresh_preview();
            return;
        }
        std::vector<std::byte> current;
        current.reserve(parsed.value().size());
        for (std::size_t i = 0; i < parsed.value().size(); ++i)
            current.push_back(cells[i].value);
        if (current == parsed.value()) {
            refresh_preview();
            return;
        }
        command = PatchBytes{start, std::move(parsed.value())};
        dialog.EndModal(wxID_OK);
    });
    refresh_preview();
    replacement->SetSelection(-1, -1);
    replacement->SetFocus();
    if (dialog.ShowModal() == wxID_OK && command)
        submit(std::move(*command));
}
void BytesView::apply_type() {
    if (!document_ || !document_->project || !document_->project->state ||
        document_->project->mode != database::ProjectMode::read_write || !submit || !selection_)
        return;
    const auto selected_address = address_for(document_->image.get(), *selection_);
    if (!selected_address)
        return;
    wxArrayString choices;
    std::vector<std::uint64_t> ids;
    const auto &definitions = document_->project->state->user->types;
    if (definitions.size() > 4096) {
        wxMessageBox("The project type catalog exceeds the 4096-entry picker limit.", "Assign type",
                     wxOK | wxICON_WARNING, this);
        return;
    }
    for (const auto &definition : definitions) {
        if (!definition.type)
            continue;
        choices.Add(text(definition.name) + " — " + text(types::format(*definition.type)));
        ids.push_back(definition.id);
    }
    if (choices.empty()) {
        wxMessageBox("Define or import a project type before assigning it to bytes.", "Assign type",
                     wxOK | wxICON_INFORMATION, this);
        return;
    }
    wxSingleChoiceDialog dialog(this, "Choose a type to apply at the selected address.", "Assign type", choices);
    if (dialog.ShowModal() != wxID_OK)
        return;
    const auto selected = static_cast<std::size_t>(dialog.GetSelection());
    if (selected < ids.size())
        submit(AssignType{*selected_address, ids[selected], false});
}
void BytesView::refresh_typed_data() {
    typed_rows_.clear();
    if (!typed_table_ || !typed_status_ || !assign_type_)
        return;
    const auto refresh_rows = [this] {
        typed_table_->populate(typed_rows_.size(), [this](std::size_t row, int column) {
            return row < typed_rows_.size() && column >= 0 && column < 4
                ? typed_rows_[row].cells[static_cast<std::size_t>(column)] : wxString{};
        });
    };
    if (!document_ || !document_->image) {
        typed_status_->SetLabel("Open an image to inspect typed data.");
        assign_type_->Disable();
        refresh_rows();
        return;
    }
    const auto selected_address = selection_ ? address_for(document_->image.get(), *selection_) : std::nullopt;
    const auto project = document_->project;
    const bool writable = project && project->state && project->mode == database::ProjectMode::read_write && submit;
    assign_type_->Enable(writable && selected_address && !project->state->user->types.empty());
    if (!project || !project->state || !selected_address) {
        typed_status_->SetLabel(project ? "Select a mapped address to assign or inspect a type."
                                        : "Typed data inspection requires a project; raw documents remain bytes-only.");
        refresh_rows();
        return;
    }
    const database::TypeAssignment *assignment = type_assignment(*project, *selected_address);
    Address object_base = *selected_address;
    if (!assignment) {
        std::optional<std::uint64_t> best_size;
        bool ambiguous = false;
        for (const auto &candidate : project->state->user->type_assignments) {
            std::optional<Address> begin;
            if (const auto *at = std::get_if<Address>(&candidate.location))
                begin = *at;
            else {
                auto mapped = document_->image->to_address(std::get<FileOffset>(candidate.location));
                if (mapped) begin = mapped.value();
            }
            if (!begin || begin->space != selected_address->space || begin->offset > selected_address->offset)
                continue;
            const auto *definition = type_definition(*project, candidate.type_id);
            if (!definition || !definition->type || !definition->type->size())
                continue;
            const auto size = *definition->type->size();
            const auto delta = selected_address->offset - begin->offset;
            if (!size || delta >= size)
                continue;
            if (!best_size || size < *best_size) {
                best_size = size;
                assignment = &candidate;
                object_base = *begin;
                ambiguous = false;
            } else if (size == *best_size && assignment && assignment->type_id != candidate.type_id) {
                ambiguous = true;
            }
        }
        if (ambiguous) {
            typed_status_->SetLabel("Multiple equally specific type assignments contain this address; select the object base.");
            refresh_rows();
            return;
        }
    }
    if (!assignment) {
        typed_status_->SetLabel("No type is assigned at this address. Use Assign type at cursor to apply a compound, array, or scalar type.");
        refresh_rows();
        return;
    }
    const auto *definition = type_definition(*project, assignment->type_id);
    if (!definition || !definition->type) {
        typed_status_->SetLabel("The assigned type definition is missing from the project.");
        refresh_rows();
        return;
    }
    const auto size = definition->type->size();
    if (!size || !*size) {
        typed_status_->SetLabel("Assigned type " + text(definition->name) + " has no complete fixed-size layout.");
        refresh_rows();
        return;
    }
    if (*size > typed_preview_byte_limit) {
        typed_status_->SetLabel(wxString::Format("Assigned type %s is %llu bytes; preview limit is %llu bytes.",
            text(definition->name), static_cast<unsigned long long>(*size),
            static_cast<unsigned long long>(typed_preview_byte_limit)));
        refresh_rows();
        return;
    }
    const auto *space = document_->image->space(object_base.space);
    if (!space) {
        typed_status_->SetLabel("Assigned address space is unavailable.");
        refresh_rows();
        return;
    }
    auto bytes = document_->image->read(object_base, static_cast<std::size_t>(*size));
    if (!bytes || bytes.value().size() != *size) {
        typed_status_->SetLabel(bytes ? wxString("Image returned a short read for the assigned type.") : text(bytes.error().message));
        refresh_rows();
        return;
    }
    collect_typed_rows(*definition->type, definition->name, 0, bytes.value(), object_base, space->order, 0, typed_rows_);
    if (typed_rows_.size() == typed_preview_row_limit)
        typed_rows_.back().cells[3] = "additional rows omitted by preview bound";
    const auto delta = selected_address->offset - object_base.offset;
    const auto type_name = text(definition->name);
    const auto base_text = location_text(Location{object_base}, document_->image.get());
    typed_status_->SetLabel(wxString::Format("%s at %s (size %llu bytes, cursor +0x%llX). Activate a field to navigate.",
        type_name.c_str(), base_text.c_str(), static_cast<unsigned long long>(*size),
        static_cast<unsigned long long>(delta)));
    refresh_rows();
}
} // namespace hexlab::desktop
