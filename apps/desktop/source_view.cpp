#include "source_view.hpp"

#include "hexlab/loaders/loaded_image.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/processors/format.hpp"
#include "data_views.hpp"

#include <wx/button.h>
#include <wx/sizer.h>
#include <wx/splitter.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <utility>

namespace hexlab::desktop {
namespace {
constexpr std::uintmax_t max_source_bytes = 1024u * 1024u;
constexpr std::int64_t context_lines = 20;
constexpr std::size_t max_source_path_bytes = 32u * 1024u;
constexpr std::size_t max_line_addresses = 4096;

std::optional<Address> address_for(const DocumentSnapshot &document, Location location) {
    if (const auto *address = std::get_if<Address>(&location))
        return *address;
    if (!document.image)
        return {};
    auto mapped = document.image->to_address(std::get<FileOffset>(location));
    return mapped ? std::optional<Address>(mapped.value()) : std::nullopt;
}

std::vector<std::byte> read_source(const std::filesystem::path &path, std::string &failure) {
    std::error_code error;
    const auto resolved = std::filesystem::canonical(path, error);
    if (error) {
        failure = "Source file is unavailable";
        return {};
    }
#ifdef _WIN32
    // Debug metadata is untrusted input. Do not let it trigger UNC or device
    // namespace access, including through a local symlink/junction target.
    const auto native = resolved.native();
    if (native.size() >= 2 && native[0] == L'\\' && native[1] == L'\\') {
        failure = "Network and device source paths are not opened";
        return {};
    }
#endif
    const auto status = std::filesystem::status(resolved, error);
    if (error || !std::filesystem::is_regular_file(status)) {
        failure = "Source file is unavailable";
        return {};
    }
    const auto size = std::filesystem::file_size(path, error);
    if (error) {
        failure = "Could not determine source file size";
        return {};
    }
    if (size > max_source_bytes) {
        failure = "Source file exceeds the 1 MiB display limit";
        return {};
    }
    std::ifstream input(resolved, std::ios::binary);
    if (!input) {
        failure = "Could not open source file";
        return {};
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        const auto count = input.gcount();
        if (count < 0) {
            failure = "Could not read source file";
            return {};
        }
        bytes.resize(static_cast<std::size_t>(count));
    }
    if (input.peek() != std::char_traits<char>::eof()) {
        failure = "Source file changed or exceeds the 1 MiB display limit";
        return {};
    }
    return bytes;
}

std::vector<std::string> split_lines(std::span<const std::byte> bytes) {
    std::vector<std::string> lines;
    std::size_t begin = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (bytes[i] != std::byte{'\n'}) continue;
        std::size_t end = i;
        if (end > begin && bytes[end - 1] == std::byte{'\r'}) --end;
        lines.emplace_back(reinterpret_cast<const char *>(bytes.data() + begin), end - begin);
        begin = i + 1;
    }
    if (begin < bytes.size() || lines.empty()) {
        std::size_t end = bytes.size();
        if (end > begin && bytes[end - 1] == std::byte{'\r'}) --end;
        lines.emplace_back(reinterpret_cast<const char *>(bytes.data() + begin), end - begin);
    }
    return lines;
}

wxString display_path(const std::string &path) {
    return wxString::FromUTF8(path.data(), path.size());
}
std::string utf8(const wxString &value) {
    const auto encoded = value.utf8_str();
    return {encoded.data(), encoded.length()};
}

std::optional<std::filesystem::path> usable_path(const std::string &path) {
    if (path.empty() || path.size() > max_source_path_bytes || path.find('\0') != std::string::npos) return {};
    try {
        std::u8string encoded;
        encoded.reserve(path.size());
        for (const unsigned char value : path) encoded.push_back(static_cast<char8_t>(value));
        auto parsed = std::filesystem::path(std::move(encoded));
#ifdef _WIN32
        // Reject network shares and Win32 device namespace paths before any
        // filesystem operation. canonical() below catches local aliases too.
        const auto native = parsed.native();
        if (native.size() >= 2 && native[0] == L'\\' && native[1] == L'\\') return {};
#endif
        return parsed;
    } catch (...) {
        return {};
    }
}
} // namespace

SourceView::SourceView(wxWindow *parent) : wxPanel(parent) {
    auto *layout = new wxBoxSizer(wxVERTICAL);
    auto *navigation = new wxBoxSizer(wxHORIZONTAL);
    source_filter_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, FromDIP(wxSize(180, -1)));
    source_filter_->SetName("source-file-filter");
    source_filter_->SetHint("Filter source files");
    source_file_ = new wxChoice(this, wxID_ANY);
    source_file_->SetName("source-file-picker");
    source_file_->SetMinSize(FromDIP(wxSize(180, -1)));
    status_ = new wxStaticText(this, wxID_ANY, "No source line selected");
    previous_mapping_ = new wxButton(this, wxID_ANY, "Previous address");
    previous_mapping_->SetName("source-previous-address");
    previous_mapping_->SetToolTip("Move to the previous machine address mapped to this source line.");
    next_mapping_ = new wxButton(this, wxID_ANY, "Next address");
    next_mapping_->SetName("source-next-address");
    next_mapping_->SetToolTip("Move to the next machine address mapped to this source line.");
    toggle_breakpoint_ = new wxButton(this, wxID_ANY, "Toggle project breakpoint");
    toggle_breakpoint_->SetName("source-toggle-project-breakpoint");
    toggle_breakpoint_->SetToolTip("Add or remove a saved software breakpoint at the selected mapped address.");
    auto *source_splitter = new wxSplitterWindow(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                                  wxSP_LIVE_UPDATE | wxSP_3D);
    source_ = new wxTextCtrl(source_splitter, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize,
                             wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP | wxTE_RICH2);
    source_->SetName("source-code-view");
    mapped_instructions_ = new VirtualTable(source_splitter, "source-line-instructions",
                                             {"Address", "Instruction", "Mapping", "Project breakpoint"});
    mapped_instructions_->SetColumnWidth(0, FromDIP(130));
    mapped_instructions_->SetColumnWidth(1, FromDIP(420));
    mapped_instructions_->SetColumnWidth(2, FromDIP(135));
    mapped_instructions_->SetColumnWidth(3, FromDIP(150));
    source_splitter->SetMinimumPaneSize(FromDIP(72));
    source_splitter->SplitHorizontally(source_, mapped_instructions_, FromDIP(300));
    status_->SetName("source-code-status");
    navigation->Add(source_filter_, 0, wxALIGN_CENTER_VERTICAL | wxALL, FromDIP(4));
    navigation->Add(source_file_, 0, wxALIGN_CENTER_VERTICAL | wxALL, FromDIP(4));
    navigation->Add(status_, 1, wxALIGN_CENTER_VERTICAL | wxALL, FromDIP(4));
    navigation->Add(previous_mapping_, 0, wxALL, FromDIP(2));
    navigation->Add(next_mapping_, 0, wxALL, FromDIP(2));
    navigation->Add(toggle_breakpoint_, 0, wxALL, FromDIP(2));
    layout->Add(navigation, 0, wxEXPAND);
    layout->Add(source_splitter, 1, wxEXPAND);
    SetSizer(layout);
    source_->Bind(wxEVT_LEFT_UP, [this](wxMouseEvent &event) {
        event.Skip();
        select_source_line();
    });
    source_->Bind(wxEVT_KEY_UP, [this](wxKeyEvent &event) {
        event.Skip();
        select_source_line();
    });
    previous_mapping_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { navigate_line_mapping(false); });
    next_mapping_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { navigate_line_mapping(true); });
    toggle_breakpoint_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (selected_line_addresses_.empty()) {
            status_->SetLabel("Select a source line with a mapped address first");
            return;
        }
        const auto selected = mapped_instructions_->selected_row();
        const auto index = selected && *selected < instruction_mappings_.size()
            ? *selected : std::min(selected_line_address_index_, selected_line_addresses_.size() - 1);
        const auto address = selected && *selected < instruction_mappings_.size()
            ? instruction_mappings_[*selected].address : selected_line_addresses_[index];
        if (toggle_project_breakpoint && document_ && toggle_project_breakpoint(document_, address)) {
            status_->SetLabel(wxString::Format("Project breakpoint toggled at 0x%llX",
                                               static_cast<unsigned long long>(address.offset)));
        } else
            status_->SetLabel("Could not update project breakpoint; check project mode and status");
    });
    mapped_instructions_->activate = [this](std::size_t row) {
        if (row < instruction_mappings_.size() && navigate)
            navigate(Location{instruction_mappings_[row].address});
    };
    source_filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) { refresh_file_choices(); });
    source_file_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) {
        if (!document_ || source_file_->GetSelection() < 0) return;
        const auto index = static_cast<std::size_t>(source_file_->GetSelection());
        if (index >= visible_source_paths_.size()) return;
        const auto &path = visible_source_paths_[index];
        const SourceRow *selected = nullptr;
        if (selection_address_)
            for (const auto &row : rows_)
                if (row.path == path && row.address.space == selection_address_->space &&
                    row.address.offset <= selection_address_->offset &&
                    (!selected || row.address.offset > selected->address.offset)) selected = &row;
        if (!selected)
            for (const auto &row : rows_) if (row.path == path && (!selected || row.address.offset < selected->address.offset)) selected = &row;
        if (selected) render_source_row(*selected, selection_address_.value_or(selected->address));
        else render_unavailable("No source mappings are available for this file");
    });
    update_mapping_controls();
}

void SourceView::set_document(std::shared_ptr<const DocumentSnapshot> document) {
    document_ = std::move(document);
    rows_.clear();
    source_paths_.clear();
    visible_source_paths_.clear();
    source_file_->Clear();
    source_filter_->ChangeValue({});
    visible_addresses_.clear();
    visible_lines_.clear();
    rendered_path_.clear();
    rendered_space_.reset();
    selection_address_.reset();
    selected_line_addresses_.clear();
    selected_line_address_index_ = 0;
    update_mapping_controls();
    if (!document_) {
        render_unavailable("No active document");
        return;
    }
    const ImageMetadata *metadata = &document_->metadata;
    if (document_->project && document_->project->loaded)
        metadata = &document_->project->loaded->metadata;
    if (metadata->pe) {
        for (const auto &row : metadata->pe->source_lines)
            if (row.address && row.line > 0 && !row.source_path.empty())
                rows_.push_back({*row.address, row.source_path, row.line, row.start_column});
        for (const auto &site : metadata->pe->pdb_inline_sites)
            for (const auto &range : site.ranges)
                if (rows_.size() < 250'000 && range.address && range.line && !range.source_path.empty())
                    rows_.push_back({*range.address, range.source_path, range.line, 0, range.size, site.depth,
                        "inlinee IPI " + std::to_string(site.inlinee_id) + ", module " + std::to_string(site.module_index) +
                        ", site " + std::to_string(site.record_offset)});
    }
    if (metadata->elf) {
        for (const auto &row : metadata->elf->source_lines)
            if (!row.end_sequence && row.line > 0 && !row.file.empty())
                rows_.push_back({row.address, row.file, row.line, row.column});
    }
    if (metadata->macho) {
        for (const auto &row : metadata->macho->source_lines)
            if (!row.end_sequence && row.address && row.line > 0 && !row.file.empty())
                rows_.push_back({*row.address, row.file, row.line, row.column});
    }
    if (metadata->dex) {
        constexpr std::size_t max_dex_source_rows = 250'000;
        for (const auto &method : metadata->dex->methods) {
            for (const auto &line : method.lines) {
                if (rows_.size() >= max_dex_source_rows) break;
                if (line.line == 0 || line.source_file.empty()) continue;
                const auto method_space = static_cast<std::uint32_t>(std::uint64_t{method.method_index} + 1);
                rows_.push_back({Address{AddressSpaceId{method_space}, line.address},
                                 line.source_file, line.line, 0, 0, 0,
                                 "DEX method #" + std::to_string(method.method_index)});
            }
            if (rows_.size() >= max_dex_source_rows) break;
        }
    }
    std::stable_sort(rows_.begin(), rows_.end(), [](const SourceRow &left, const SourceRow &right) {
        if (left.address.space.value != right.address.space.value)
            return left.address.space.value < right.address.space.value;
        if (left.address.offset != right.address.offset) return left.address.offset < right.address.offset;
        return left.line < right.line;
    });
    for (const auto &row : rows_)
        if (std::find(source_paths_.begin(), source_paths_.end(), row.path) == source_paths_.end())
            source_paths_.push_back(row.path);
    std::sort(source_paths_.begin(), source_paths_.end());
    refresh_file_choices(source_paths_.empty() ? std::string{} : source_paths_.front());
    render_unavailable(rows_.empty() ? "No usable source line mappings are available for this document"
                                     : "Navigate to an address with source information");
}

void SourceView::select(Location location) {
    if (!document_) return;
    if (rows_.empty()) {
        render_unavailable("No source line mappings are available");
        return;
    }
    auto address = address_for(*document_, location);
    if (!address) {
        render_unavailable("No source mapping at the current file offset");
        return;
    }
    selection_address_ = *address;
    const SourceRow *selected = nullptr;
    bool ambiguous_inline = false;
    for (const auto &row : rows_) {
        if (row.address.space != address->space || row.address.offset > address->offset) continue;
        if (row.inline_size && address->offset - row.address.offset >= row.inline_size) continue;
        if (selected && row.inline_depth && row.inline_depth == selected->inline_depth &&
            (row.path != selected->path || row.line != selected->line || row.scope != selected->scope))
            ambiguous_inline = true;
        if (!selected || row.inline_depth > selected->inline_depth ||
            (row.inline_depth == selected->inline_depth && row.address.offset > selected->address.offset)) {
            if (!selected || row.inline_depth > selected->inline_depth) ambiguous_inline = false;
            selected = &row;
        }
    }
    if (ambiguous_inline) {
        render_unavailable("Multiple inline scopes overlap this address; inspect PE / PDB inline scopes");
        return;
    }
    if (!selected) {
        render_unavailable("No source mapping at the current address");
        return;
    }
    if (display_path(selected->path).Lower().Find(source_filter_->GetValue().Lower()) == wxNOT_FOUND)
        source_filter_->ChangeValue({});
    refresh_file_choices(selected->path);
    render_source_row(*selected, *address);
}

void SourceView::refresh_file_choices(const std::string &preferred_path) {
    std::string preserve = preferred_path;
    if (preserve.empty() && source_file_->GetSelection() >= 0) {
        const auto selected = static_cast<std::size_t>(source_file_->GetSelection());
        if (selected < visible_source_paths_.size()) preserve = visible_source_paths_[selected];
    }
    const auto filter = source_filter_->GetValue().Lower();
    visible_source_paths_.clear();
    source_file_->Clear();
    for (const auto &path : source_paths_)
        if (filter.empty() || display_path(path).Lower().Find(filter) != wxNOT_FOUND) {
            visible_source_paths_.push_back(path);
            source_file_->Append(display_path(path));
        }
    const auto found = std::find(visible_source_paths_.begin(), visible_source_paths_.end(), preserve);
    if (found != visible_source_paths_.end())
        source_file_->SetSelection(static_cast<int>(std::distance(visible_source_paths_.begin(), found)));
    else if (!visible_source_paths_.empty())
        source_file_->SetSelection(0);
}

void SourceView::render_source_row(const SourceRow &source_row, Address context_address) {
    const auto *selected = &source_row;
    auto path = usable_path(selected->path);
    if (!path) {
        render_unavailable("Debug information contains an invalid source path");
        return;
    }
    std::string failure;
    const auto bytes = read_source(*path, failure);
    if (!failure.empty()) {
        render_unavailable(display_path(selected->path) + ": " + text(failure));
        return;
    }
    auto lines = split_lines(bytes);
    if (selected->line <= 0 || static_cast<std::uint64_t>(selected->line) > lines.size()) {
        render_unavailable(display_path(selected->path) + ": mapped source line is outside the available file");
        return;
    }
    const auto selected_line = selected->line - 1;
    const auto first = std::max<std::int64_t>(0, selected_line - context_lines);
    const auto last = std::min<std::int64_t>(static_cast<std::int64_t>(lines.size()), selected_line + context_lines + 1);
    wxString rendered;
    visible_addresses_.clear();
    visible_lines_.clear();
    rendered_path_ = selected->path;
    rendered_space_ = context_address.space;
    std::vector<std::optional<Address>> line_addresses(static_cast<std::size_t>(last - first));
    for (const auto &row : rows_)
        if (row.path == selected->path && row.address.space == context_address.space && row.line > 0 &&
            row.line - 1 >= first && row.line - 1 < last) {
            auto &target = line_addresses[static_cast<std::size_t>(row.line - 1 - first)];
            if (!target || row.address.offset < target->offset) target = row.address;
        }
    for (auto line = first; line < last; ++line) {
        if (!rendered.empty()) rendered += "\n";
        rendered += wxString::Format("%6lld  ", static_cast<long long>(line + 1));
        const auto &contents = lines[static_cast<std::size_t>(line)];
        rendered += wxString::FromUTF8(contents.data(), contents.size());
        visible_addresses_.push_back(line_addresses[static_cast<std::size_t>(line - first)]);
        visible_lines_.push_back(line + 1);
    }
    updating_ = true;
    source_->ChangeValue(rendered);
    const auto visible_selected = selected_line - first;
    const long start = source_->XYToPosition(0, static_cast<long>(visible_selected));
    const long length = source_->GetLineLength(static_cast<long>(visible_selected));
    if (start >= 0 && length > 0) {
        source_->SetSelection(start, start + length);
        source_->ShowPosition(start);
    }
    updating_ = false;
    selected_line_addresses_.clear();
    bool line_addresses_truncated = false;
    std::set<std::pair<std::uint64_t, std::uint64_t>> seen_line_addresses;
    for (const auto &row : rows_)
        if (row.path == selected->path && row.address.space == context_address.space && row.line == selected->line) {
            const auto key = std::pair{row.address.space.value, row.address.offset};
            if (seen_line_addresses.contains(key)) continue;
            if (seen_line_addresses.size() == max_line_addresses) {
                line_addresses_truncated = true;
                break;
            }
            seen_line_addresses.insert(key);
            selected_line_addresses_.push_back(row.address);
        }
    selected_line_address_index_ = 0;
    for (std::size_t i = 0; i < selected_line_addresses_.size(); ++i)
        if (selected_line_addresses_[i].space == context_address.space &&
            selected_line_addresses_[i].offset <= context_address.offset)
            selected_line_address_index_ = i;
    update_mapping_controls();
    render_instruction_mappings(selected->path, selected->line, context_address.space);
    status_->SetLabel(display_path(selected->path) + wxString::Format(
        " — line %lld, address 0x%llX, %zu mapped addresses (%zu shown below)",
        static_cast<long long>(selected->line), static_cast<unsigned long long>(selected->address.offset),
        selected_line_addresses_.size(), instruction_mappings_.size()));
    if (line_addresses_truncated)
        status_->SetLabel(status_->GetLabel() + "; additional unique addresses omitted by the 4096-address limit");
    if (!selected->scope.empty()) status_->SetLabel(status_->GetLabel() + " / " + text(selected->scope));
}

void SourceView::render_instruction_mappings(const std::string &path, std::int64_t line,
                                             AddressSpaceId space) {
    instruction_mappings_.clear();
    if (!document_ || line <= 0) {
        mapped_instructions_->populate(0, [](std::size_t, int) { return wxString{}; });
        return;
    }
    std::vector<Address> addresses;
    std::set<std::pair<std::uint64_t, std::uint64_t>> seen_addresses;
    for (const auto &row : rows_)
        if (row.path == path && row.line == line && row.address.space == space) {
            const auto key = std::pair{row.address.space.value, row.address.offset};
            if (seen_addresses.contains(key)) continue;
            if (seen_addresses.size() == max_line_addresses) break;
            seen_addresses.insert(key);
            addresses.push_back(row.address);
        }

    const std::vector<Instruction> *analysis_instructions = nullptr;
    const std::vector<std::shared_ptr<const InstructionFact>> *project_instructions = nullptr;
    if (document_->project && document_->project->state && document_->project->functions &&
        document_->project->functions->key &&
        document_->project->functions->key->byte_revision == document_->project->state->revisions.bytes &&
        document_->project->functions->key->decision_revision == document_->project->state->revisions.decisions)
        project_instructions = &document_->project->functions->instructions;
    else if (!document_->project && document_->analysis)
        analysis_instructions = &document_->analysis->instructions;

    instruction_mappings_.reserve(addresses.size());
    for (const auto address : addresses) {
        wxString formatted;
        wxString state = "source mapping";
        if (project_instructions) {
            auto found = std::lower_bound(project_instructions->begin(), project_instructions->end(), address,
                [](const auto &fact, Address at) {
                    const auto &current = fact->instruction.address;
                    return current.space.value < at.space.value ||
                           (current.space == at.space && current.offset < at.offset);
                });
            if (found != project_instructions->end() && (*found)->instruction.address == address) {
                formatted = text(format_instruction((*found)->instruction));
                state = "instruction";
            }
        } else if (analysis_instructions) {
            auto found = std::lower_bound(analysis_instructions->begin(), analysis_instructions->end(), address,
                [](const Instruction &instruction, Address at) {
                    const auto current = instruction.address;
                    return current.space.value < at.space.value ||
                           (current.space == at.space && current.offset < at.offset);
                });
            if (found != analysis_instructions->end() && found->address == address) {
                formatted = text(format_instruction(*found));
                state = "instruction";
            }
        }
        if (formatted.empty()) {
            formatted = "No current instruction at this mapped address";
            if (!project_instructions && !analysis_instructions)
                state = "listing unavailable";
        }
        instruction_mappings_.push_back({address, std::move(formatted), std::move(state)});
    }
    mapped_instructions_->populate(instruction_mappings_.size(), [this](std::size_t row, int column) {
        if (row >= instruction_mappings_.size()) return wxString{};
        const auto &item = instruction_mappings_[row];
        switch (column) {
        case 0: return wxString::Format("0x%llX", static_cast<unsigned long long>(item.address.offset));
        case 1: return item.instruction;
        case 2: return item.state;
        default:
            if (document_ && document_->project && document_->project->state && document_->project->state->user) {
                const auto &saved = document_->project->state->user->breakpoints;
                const auto found = std::find_if(saved.begin(), saved.end(), [&](const auto &bp) {
                    return bp.address == item.address && bp.kind == database::ProjectBreakpointKind::software;
                });
                if (found != saved.end()) return found->enabled ? wxString("Enabled") : wxString("Disabled");
            }
            return wxString("—");
        }
    });
    mapped_instructions_->fit_columns({0, 1, 2, 3});
}

void SourceView::select_source_line() {
    if (updating_ || !navigate || visible_addresses_.empty()) return;
    long x = 0, y = 0;
    if (!source_->PositionToXY(source_->GetInsertionPoint(), &x, &y) || y < 0 ||
        static_cast<std::size_t>(y) >= visible_addresses_.size()) return;
    const auto line = visible_lines_[static_cast<std::size_t>(y)];
    std::vector<Address> candidates;
    for (const auto &row : rows_)
        if (row.path == rendered_path_ && (!rendered_space_ || row.address.space == *rendered_space_) &&
            row.line == line &&
            std::find(candidates.begin(), candidates.end(), row.address) == candidates.end())
            candidates.push_back(row.address);
    std::stable_sort(candidates.begin(), candidates.end(), [](Address left, Address right) {
        if (left.space.value != right.space.value) return left.space.value < right.space.value;
        return left.offset < right.offset;
    });
    if (!candidates.empty()) navigate(Location{candidates.front()});
}

void SourceView::navigate_line_mapping(bool next) {
    if (!navigate || selected_line_addresses_.empty()) return;
    if (next) {
        if (selected_line_address_index_ + 1 >= selected_line_addresses_.size()) return;
        ++selected_line_address_index_;
    } else {
        if (!selected_line_address_index_) return;
        --selected_line_address_index_;
    }
    navigate(Location{selected_line_addresses_[selected_line_address_index_]});
}

void SourceView::update_mapping_controls() {
    const bool has_previous = !selected_line_addresses_.empty() && selected_line_address_index_ > 0;
    const bool has_next = !selected_line_addresses_.empty() &&
                          selected_line_address_index_ + 1 < selected_line_addresses_.size();
    if (previous_mapping_) previous_mapping_->Enable(has_previous);
    if (next_mapping_) next_mapping_->Enable(has_next);
    if (toggle_breakpoint_) toggle_breakpoint_->Enable(!selected_line_addresses_.empty());
}

void SourceView::render_unavailable(const wxString &message) {
    visible_addresses_.clear();
    visible_lines_.clear();
    rendered_path_.clear();
    rendered_space_.reset();
    selected_line_addresses_.clear();
    selected_line_address_index_ = 0;
    instruction_mappings_.clear();
    mapped_instructions_->populate(0, [](std::size_t, int) { return wxString{}; });
    update_mapping_controls();
    updating_ = true;
    source_->ChangeValue(message);
    updating_ = false;
    status_->SetLabel(message);
}
} // namespace hexlab::desktop
