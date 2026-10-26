#include "reference_view.hpp"
#include "project_view.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/image/image.hpp"
#include <wx/sizer.h>
#include <wx/textctrl.h>
#include <algorithm>
namespace hexlab::desktop {
namespace {
const char *kind_text(ReferenceKind kind) {
    switch (kind) {
    case ReferenceKind::call:
        return "call";
    case ReferenceKind::jump:
        return "jump";
    case ReferenceKind::conditional_jump:
        return "conditional jump";
    case ReferenceKind::memory_read:
        return "read";
    case ReferenceKind::memory_write:
        return "write";
    case ReferenceKind::memory_read_write:
        return "read/write";
    case ReferenceKind::memory_address:
        return "address";
    case ReferenceKind::imported_call:
        return "imported call";
    case ReferenceKind::imported_jump:
        return "imported jump";
    case ReferenceKind::user_code:
        return "user code";
    case ReferenceKind::user_data:
        return "user data";
    case ReferenceKind::relocation:
        return "relocation";
    case ReferenceKind::dyld_fixup:
        return "dyld fixup";
    }
    return "unknown";
}
wxString target_text(const Reference &reference, const Image *image) {
    const auto &target = reference.target;
    if (auto location = std::get_if<Location>(&target))
        return location_text(*location, image);
    if (auto external = std::get_if<ExternalIdentity>(&target))
        return preview_text(external->library, 160) + "!" +
               (external->name ? preview_text(*external->name, 160)
                               : wxString::Format("#%u", external->ordinal.value_or(0)));
    auto &unresolved = std::get<UnresolvedTarget>(target);
    wxString reason;
    switch (unresolved.reason) {
    case UnresolvedReason::register_value:
        reason = "register value";
        break;
    case UnresolvedReason::memory_address:
        reason = "memory address";
        break;
    case UnresolvedReason::memory_value:
        reason = "memory value";
        break;
    case UnresolvedReason::relative_overflow:
        reason = "relative overflow";
        break;
    case UnresolvedReason::missing_operand:
        reason = "missing operand";
        break;
    case UnresolvedReason::ambiguous_import:
        reason = "ambiguous import";
        break;
    case UnresolvedReason::far_selector:
        reason = "far selector or transfer attributes";
        break;
    case UnresolvedReason::elf_relocation:
        reason = "ELF relocation";
        break;
    case UnresolvedReason::macho_relocation:
        reason = "Mach-O relocation";
        break;
    case UnresolvedReason::macho_dyld:
        reason = "Mach-O dyld fixup";
        if (reference.provenance.dyld && reference.provenance.dyld->resolution.binding)
            reason += ": " + preview_text(reference.provenance.dyld->resolution.binding->name, 160);
        break;
    }
    if (auto reg = std::get_if<RegisterOperand>(&unresolved.expression))
        reason += " (" + text(register_name(*reg)) + ")";
    if (reference.provenance.elf) {
        const auto &origins = reference.provenance.elf->origins;
        if (origins.size() == 1) {
            const auto &origin = origins[0];
            if (origin.symbol && !origin.symbol->name.empty())
                reason += ": " + preview_text(origin.symbol->name, 160);
            else if (origin.relocation.symbol_table) {
                reason += ": symbol #" + wxString::Format("%u", origin.relocation.symbol_index);
                if (!origin.relocation.symbol_index_validated)
                    reason += " (unvalidated)";
            }
        } else
            reason += ": ambiguous origins";
    }
    return "unresolved: " + reason;
}
wxString endpoint_context(const ProjectSnapshot &project, Location location, const Image *image) {
    wxString result;
    const auto append = [&result](wxString value) {
        if (value.empty()) return;
        if (!result.empty()) result += "; ";
        result += std::move(value);
    };

    const auto presentation = presentation_at(project, location);
    append("name " + preview_text(presentation.name, 128));
    if (auto annotation = annotation_at(project, location); annotation && !annotation->comment.empty())
        append("comment: " + preview_text(annotation->comment, 160));

    const auto address = std::get_if<Address>(&location);
    if (address && project.functions) {
        for (const auto &function : project.functions->functions) {
            if (!function) continue;
            bool contains = function->entry == *address;
            for (const auto &chunk : function->chunks) {
                if (chunk.begin.space == address->space && address->offset >= chunk.begin.offset &&
                    address->offset - chunk.begin.offset < chunk.size) {
                    contains = true;
                    break;
                }
            }
            if (!contains) continue;
            auto label = preview_text(presentation_name(project, Location{function->entry}), 128);
            if (address->space == function->entry.space && address->offset >= function->entry.offset &&
                address->offset != function->entry.offset)
                label += wxString::Format("+0x%llX",
                    static_cast<unsigned long long>(address->offset - function->entry.offset));
            append("function " + label);
            break;
        }
    }

    if (image) {
        const Segment *segment = nullptr;
        if (address) {
            segment = image->segment_at(*address);
        } else {
            const auto offset = std::get<FileOffset>(location).value;
            for (const auto &candidate : image->layout().segments)
                if (offset >= candidate.file_begin.value &&
                    offset - candidate.file_begin.value < candidate.file_size) {
                    segment = &candidate;
                    break;
                }
        }
        if (segment)
            append("segment " + preview_text(segment->name, 80));
    }
    return result.empty() ? wxString("-") : result;
}
} // namespace
ReferenceView::ReferenceView(wxWindow *parent) : wxPanel(parent) {
    SetName("reference-view");
    const int pad = FromDIP(4);
    auto *stack = new wxBoxSizer(wxVERTICAL);
    auto *bar = new wxBoxSizer(wxHORIZONTAL);
    wxArrayString choices;
    choices.Add("Outgoing");
    choices.Add("Incoming");
    direction_ = new wxChoice(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, choices);
    direction_->SetName("reference-direction");
    direction_->SetSelection(0);
    previous_ = new wxButton(this, wxID_ANY, "Previous");
    previous_->SetName("reference-previous");
    next_ = new wxButton(this, wxID_ANY, "Next");
    next_->SetName("reference-next");
    bar->Add(direction_, 0, wxALL, pad);
    bar->Add(previous_, 0, wxALL, pad);
    bar->Add(next_, 0, wxALL, pad);
    range_ = new wxCheckBox(this, wxID_ANY, "Address range");
    range_->SetName("reference-range");
    range_size_ = new wxTextCtrl(this, wxID_ANY, "16", wxDefaultPosition, wxSize(FromDIP(72), -1));
    range_size_->SetName("reference-range-size");
    range_size_->SetToolTip("Number of bytes from the selected address (1 to 4096).");
    mapped_range_ = new wxCheckBox(this, wxID_ANY, "Map file range");
    mapped_range_->SetName("reference-mapped-file-range");
    mapped_range_->SetToolTip("Include references at every virtual mapping of these file-backed bytes.");
    bar->Add(range_, 0, wxALL | wxALIGN_CENTER_VERTICAL, pad);
    bar->Add(range_size_, 0, wxALL, pad);
    bar->Add(mapped_range_, 0, wxALL | wxALIGN_CENTER_VERTICAL, pad);
    stack->Add(bar, 0, wxEXPAND);
    auto *context_bar = new wxBoxSizer(wxHORIZONTAL);
    pin_ = new wxCheckBox(this, wxID_ANY, "Pin context");
    pin_->SetName("reference-pin");
    pin_->SetToolTip("Keep this document's reference origin and page while following endpoints.");
    origin_ = new wxButton(this, wxID_ANY, "Go to origin");
    origin_->SetName("reference-origin");
    origin_->SetToolTip("Return to the current reference origin (Ctrl+Home).");
    context_bar->Add(pin_, 0, wxALL | wxALIGN_CENTER_VERTICAL, pad);
    context_bar->Add(origin_, 0, wxALL, pad);
    stack->Add(context_bar, 0, wxEXPAND);
    context_ = new wxStaticText(this, wxID_ANY, "Select a location", wxDefaultPosition, wxDefaultSize,
                                wxST_ELLIPSIZE_END);
    context_->SetName("reference-context");
    stack->Add(context_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, pad);
    auto *endpoint_bar = new wxBoxSizer(wxHORIZONTAL);
    source_ = new wxButton(this, wxID_ANY, "Go to source");
    source_->SetName("reference-source");
    source_->SetToolTip("Navigate to the selected reference source.");
    target_ = new wxButton(this, wxID_ANY, "Go to target");
    target_->SetName("reference-target");
    target_->SetToolTip("Available only for a resolved address or file-offset target.");
    endpoint_bar->Add(source_, 0, wxALL, pad);
    endpoint_bar->Add(target_, 0, wxALL, pad);
    stack->Add(endpoint_bar, 0, wxEXPAND);
    table_ = new VirtualTable(this, "references",
                              {"Source", "Target", "Kind", "Evidence", "Association", "Source context", "Target context"});
    stack->Add(table_, 1, wxEXPAND);
    detail_ = new wxTextCtrl(this, wxID_ANY, "Select a reference to inspect its relation details.",
                             wxDefaultPosition, wxSize(-1, FromDIP(104)),
                             wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP | wxBORDER_SIMPLE);
    detail_->SetName("reference-detail");
    detail_->SetToolTip("Bounded metadata for the selected reference, including access, operand and provenance.");
    stack->Add(detail_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, pad);
    status_ = new wxStaticText(this, wxID_ANY, "");
    status_->SetName("reference-status");
    stack->Add(status_, 0, wxALL, pad);
    SetSizer(stack);
    direction_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) {
        if (document_) {
            auto &p = preferences_[document_->value];
            p.incoming = direction_->GetSelection() == 1;
            p.offset = 0;
            p.selected.reset();
            reload();
        }
    });
    range_->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent &) {
        if (!document_) return;
        auto &p = preferences_[document_->value];
        p.range = range_->GetValue();
        if (!p.range) p.mapped_range = false;
        p.offset = 0;
        p.selected.reset();
        reload();
    });
    mapped_range_->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent &) {
        if (!document_) return;
        auto &p = preferences_[document_->value];
        p.mapped_range = mapped_range_->GetValue();
        p.offset = 0;
        p.selected.reset();
        reload();
    });
    range_size_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) {
        if (!document_) return;
        unsigned long long size = 0;
        if (!range_size_->GetValue().ToULongLong(&size) || size == 0 || size > 4096) return;
        auto &p = preferences_[document_->value];
        if (p.range_size == size) return;
        p.range_size = size;
        p.offset = 0;
        p.selected.reset();
        reload();
    });
    previous_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (document_) {
            auto &p = preferences_[document_->value];
            p.offset = p.offset >= 256 ? p.offset - 256 : 0;
            p.selected.reset();
            reload();
        }
    });
    next_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (document_ && rows_ && rows_->next_offset) {
            preferences_[document_->value].offset = *rows_->next_offset;
            preferences_[document_->value].selected.reset();
            reload();
        }
    });
    table_->activate = [this](std::size_t row) {
        if (!document_ || !rows_ || row >= rows_->rows.size())
            return;
        const auto id = *document_;
        const auto &ref = rows_->rows[row];
        preferences_[id.value].selected = ref.id;
        update_detail();
        update_actions();
        auto incoming = preferences_[document_->value].incoming;
        auto target = std::get_if<Location>(&ref.target);
        auto location = incoming || !target ? ref.source : *target;
        if (navigate)
            navigate(id, project_, location);
    };
    pin_->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent &) {
        if (!document_) return;
        auto &preference = preferences_[document_->value];
        preference.pinned = pin_->GetValue() ? location_ : std::nullopt;
        update(document_, project_, selection_);
        update_actions();
    });
    source_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { follow_selected(false); });
    target_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { follow_selected(true); });
    origin_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (document_ && location_ && navigate) {
            const auto id = *document_;
            const auto location = *location_;
            navigate(id, project_, location);
        }
    });
    table_->SetToolTip("References for the selected location. Use Up/Down to select an item; Enter or double-click follows its current endpoint.");
    direction_->SetToolTip("Choose outgoing references from the current location or incoming references to it.");
    previous_->SetToolTip("Show the previous page of references (Alt+Left).");
    next_->SetToolTip("Show the next page of references (Alt+Right).");
    Bind(wxEVT_CHAR_HOOK, [this](wxKeyEvent &event) {
        if (event.AltDown() && event.GetKeyCode() == WXK_LEFT) {
            if (document_) {
                auto &preference = preferences_[document_->value];
                preference.offset = preference.offset >= 256 ? preference.offset - 256 : 0;
                preference.selected.reset();
                reload();
            }
            return;
        }
        if (event.AltDown() && event.GetKeyCode() == WXK_RIGHT) {
            if (document_ && rows_ && rows_->next_offset) {
                preferences_[document_->value].offset = *rows_->next_offset;
                preferences_[document_->value].selected.reset();
                reload();
            }
            return;
        }
        if (event.ControlDown() && event.GetKeyCode() == WXK_HOME) {
            if (document_ && location_ && navigate)
            navigate(*document_, project_, *location_);
            return;
        }
        event.Skip();
    });
    update_actions();
}
void ReferenceView::inspect(Location location, bool incoming) {
    if (!document_) return;
    auto &preference = preferences_[document_->value];
    preference.pinned = location;
    preference.incoming = incoming;
    preference.offset = 0;
    preference.selected.reset();
    // Force a reload even when only the requested direction changed.
    preference.origin = location;
    location_ = location;
    if (!std::holds_alternative<FileOffset>(location))
        preference.mapped_range = false;
    reload();
}
const Reference *ReferenceView::selected_reference() const {
    if (!document_ || !rows_) return nullptr;
    const auto preference = preferences_.find(document_->value);
    if (preference == preferences_.end() || !preference->second.selected) return nullptr;
    const auto found = std::find_if(rows_->rows.begin(), rows_->rows.end(), [&](const auto &reference) {
        return reference.id == *preference->second.selected;
    });
    if (found == rows_->rows.end()) return nullptr;
    return found == rows_->rows.end() ? nullptr : &*found;
}
void ReferenceView::update_actions() {
    const auto *reference = selected_reference();
    source_->Enable(reference != nullptr);
    target_->Enable(reference && std::holds_alternative<Location>(reference->target));
    origin_->Enable(document_.has_value() && location_.has_value());
    pin_->Enable(document_.has_value() && location_.has_value());
    const auto preference = document_ ? preferences_.find(document_->value) : preferences_.end();
    const bool pinned = preference != preferences_.end() && preference->second.pinned.has_value();
    pin_->SetValue(pinned);
    const auto *image = project_ && project_->loaded ? project_->loaded->image.get() : nullptr;
    const auto label = location_ ? wxString(pinned ? "Pinned: " : "Following: ") + location_text(*location_, image)
                                : wxString("Select a location");
    context_->SetLabel(label);
    context_->SetToolTip(label);
}
void ReferenceView::update_detail() {
    const auto *reference = selected_reference();
    if (!reference) {
        detail_->ChangeValue("Select a reference to inspect its relation details.");
        return;
    }
    const auto *image = project_ && project_->loaded ? project_->loaded->image.get() : nullptr;
    const auto access = reference->access == OperandAccess::read ? "read"
                      : reference->access == OperandAccess::write ? "write"
                      : reference->access == OperandAccess::read_write ? "read/write" : "address";
    const auto provenance = [&]() -> wxString {
        switch (reference->provenance.kind) {
        case ReferenceProvenanceKind::decoded: return "decoded instruction";
        case ReferenceProvenanceKind::import_slot: return "import slot";
        case ReferenceProvenanceKind::user: return "user-defined";
        case ReferenceProvenanceKind::elf_relocation: return "ELF relocation";
        case ReferenceProvenanceKind::macho_relocation: return "Mach-O relocation";
        case ReferenceProvenanceKind::macho_dyld: return "Mach-O dyld fixup";
        case ReferenceProvenanceKind::dataflow: return "dataflow-resolved";
        case ReferenceProvenanceKind::elf_vtable_slot: return "ELF vtable slot";
        }
        return "unknown";
    }();
    wxString text_value = wxString::Format("Reference #%llu\nSource: %s\nTarget: %s\nKind: %s\nAccess: %s\n",
        static_cast<unsigned long long>(reference->id.value), location_text(reference->source, image),
        target_text(*reference, image), kind_text(reference->kind), access);
    text_value += reference->operand_index
        ? wxString::Format("Operand: %u\n", *reference->operand_index)
        : wxString("Operand: n/a\n");
    text_value += "Provenance: " + provenance;
    if (reference->provenance.instruction_id)
        text_value += wxString::Format("; instruction #%llu", static_cast<unsigned long long>(reference->provenance.instruction_id));
    if (reference->provenance.user_id)
        text_value += wxString::Format("; user record #%llu", static_cast<unsigned long long>(reference->provenance.user_id));
    text_value += "\n";
    if (reference->association)
        text_value += "Association: " + location_text(*reference->association, image) + "\n";
    const auto &producers = reference->provenance.producer_instruction_ids;
    if (!producers.empty()) {
        text_value += wxString::Format("Dataflow producers (%zu): ", producers.size());
        const auto count = std::min<std::size_t>(producers.size(), 16);
        for (std::size_t i = 0; i < count; ++i) {
            if (i) text_value += ", ";
            text_value += wxString::Format("#%llu", static_cast<unsigned long long>(producers[i]));
        }
        if (count < producers.size()) text_value += wxString::Format(" +%zu more", producers.size() - count);
        text_value += "\n";
    }
    const auto &producer_graph = reference->provenance.producer_graph;
    if (!producer_graph.dependencies.empty()) {
        text_value += wxString::Format("Producer dependencies (%zu edges):\n",
                                       producer_graph.dependencies.size());
        const auto count = std::min<std::size_t>(producer_graph.dependencies.size(), 48);
        for (std::size_t i = 0; i < count; ++i) {
            const auto &edge = producer_graph.dependencies[i];
            text_value += wxString::Format("  #%llu depends on #%llu\n",
                static_cast<unsigned long long>(edge.consumer_instruction_id),
                static_cast<unsigned long long>(edge.producer_instruction_id));
        }
        if (count < producer_graph.dependencies.size()) text_value += "  …\n";
    }
    if (!producer_graph.immediates.empty()) {
        text_value += wxString::Format("Immediate operands (%zu):\n", producer_graph.immediates.size());
        const auto count = std::min<std::size_t>(producer_graph.immediates.size(), 32);
        for (std::size_t i = 0; i < count; ++i) {
            const auto &immediate = producer_graph.immediates[i];
            text_value += wxString::Format("  #%llu operand %u = 0x%llx (%u-bit encoded, %u-bit effective%s)\n",
                static_cast<unsigned long long>(immediate.instruction_id), immediate.operand_index,
                static_cast<unsigned long long>(immediate.value), immediate.encoded_width,
                immediate.effective_width,
                immediate.is_signed ? ", signed" : "");
        }
    }
    if (producer_graph.ambiguous) text_value += "Producer chain has multiple equal-value path origins.\n";
    if (producer_graph.cycle) text_value += "A producer cycle was detected and omitted.\n";
    if (producer_graph.truncated) text_value += "Producer chain is bounded; some dependencies are omitted.\n";
    if (reference->provenance.elf)
        text_value += wxString::Format("ELF origins: %zu\n", reference->provenance.elf->origins.size());
    if (reference->provenance.elf_vtable) {
        const auto &vtable = *reference->provenance.elf_vtable;
        text_value += wxString::Format("Vtable slot: %s, index %u",
            vtable.type_name ? preview_text(*vtable.type_name, 128) : wxString("unnamed"), vtable.slot_index);
        text_value += "; table " + location_text(Location{vtable.table_begin}, image) + "\n";
    }
    if (reference->provenance.macho)
        text_value += wxString::Format("Mach-O relocation origins: %zu\n", reference->provenance.macho->origins.size());
    if (reference->provenance.dyld)
        text_value += wxString::Format("Mach-O dyld origins: %zu\n", reference->provenance.dyld->origins.size());
    detail_->ChangeValue(text_value);
}
void ReferenceView::follow_selected(bool target) {
    const auto *reference = selected_reference();
    if (!reference || !document_ || !navigate) return;
    const auto id = *document_;
    if (target) {
        const auto *destination = std::get_if<Location>(&reference->target);
        if (!destination) return;
        const auto location = *destination;
        navigate(id, project_, location);
    } else {
        const auto location = reference->source;
        navigate(id, project_, location);
    }
}
void ReferenceView::retain_documents(std::span<const DocumentInfo> docs) {
    for (auto it = preferences_.begin(); it != preferences_.end();)
        if (std::none_of(docs.begin(), docs.end(), [&](auto &doc) { return doc.id.value == it->first; }))
            it = preferences_.erase(it);
        else
            ++it;
}
void ReferenceView::update(std::optional<DocumentId> id, std::shared_ptr<const ProjectSnapshot> project,
                           std::optional<Location> location) {
    selection_ = location;
    if (id) {
        auto &preference = preferences_[id->value];
        if (preference.pinned) location = preference.pinned;
        if (!location || !std::holds_alternative<FileOffset>(*location))
            preference.mapped_range = false;
        if (preference.origin != location) {
            preference.offset = 0;
            preference.selected.reset();
            preference.origin = location;
        }
    }
    if (id == document_ && project == project_ && location == location_)
        return;
    document_ = id;
    project_ = std::move(project);
    location_ = location;
    reload();
}
void ReferenceView::reload() {
    rows_.reset();
    table_->populate(0, {});
    update_actions();
    update_detail();
    previous_->Disable();
    next_->Disable();
    direction_->Enable(document_.has_value());
    range_->Enable(document_.has_value());
    range_size_->Enable(document_.has_value() && range_->GetValue());
    mapped_range_->SetValue(false);
    mapped_range_->Enable(false);
    if (!document_ || !project_ || !location_) {
        status_->SetLabel("Select a location");
        update_detail();
        return;
    }
    auto &preference = preferences_[document_->value];
    direction_->SetSelection(preference.incoming ? 1 : 0);
    range_->SetValue(preference.range);
    range_size_->ChangeValue(wxString::Format("%llu", static_cast<unsigned long long>(preference.range_size)));
    range_size_->Enable(preference.range);
    mapped_range_->SetValue(preference.mapped_range);
    mapped_range_->Enable(preference.range && std::holds_alternative<FileOffset>(*location_) &&
                          project_->loaded != nullptr);
    if (!project_->references ||
        (project_->status != DerivedStatus::fresh && project_->status != DerivedStatus::incomplete) ||
        !project_->derived_key || project_->references->key() != project_->derived_key) {
        status_->SetLabel("References unavailable: " + analysis_state_text(*project_));
        return;
    }
    Result<ReferencePage> page = [&]() -> Result<ReferencePage> {
        if (preference.range) {
            if (preference.mapped_range) {
                const auto *file = std::get_if<FileOffset>(&*location_);
                if (!file || !project_->loaded)
                    return Error{ErrorCode::invalid_argument,
                                 "Mapped file ranges require a loaded image and file-offset location"};
                return preference.incoming
                    ? project_->references->incoming_mapped_file_range(
                          *project_->loaded->image, *file, preference.range_size, {preference.offset, 256})
                    : project_->references->outgoing_mapped_file_range(
                          *project_->loaded->image, *file, preference.range_size, {preference.offset, 256});
            }
            const auto *address = std::get_if<Address>(&*location_);
            if (!address) return Error{ErrorCode::invalid_argument, "Address ranges require a virtual address"};
            return preference.incoming
                ? project_->references->incoming_range(*address, preference.range_size, {preference.offset, 256})
                : project_->references->outgoing_range(*address, preference.range_size, {preference.offset, 256});
        }
        return preference.incoming ? project_->references->incoming(*location_, {preference.offset, 256})
                                   : project_->references->outgoing(*location_, {preference.offset, 256});
    }();
    if (!page) {
        status_->SetLabel(text(page.error().message));
        return;
    }
    rows_ = std::make_shared<const ReferencePage>(std::move(page.value()));
    if (rows_->rows.empty() && preference.offset > 0) {
        preference.offset = 0;
        preference.selected.reset();
        reload();
        return;
    }
    auto rows = rows_;
    auto project = project_;
    table_->populate(rows->rows.size(), [rows, project](std::size_t row, int column) {
        const auto *image = project->loaded ? project->loaded->image.get() : nullptr;
        auto &ref = rows->rows[row];
        switch (column) {
        case 0:
            return location_text(ref.source, image);
        case 1:
            return target_text(ref, image);
        case 2:
            return wxString(kind_text(ref.kind));
        case 3:
            return wxString(ref.provenance.kind == ReferenceProvenanceKind::user             ? "explicit"
                            : ref.provenance.kind == ReferenceProvenanceKind::import_slot    ? "import slot"
                            : ref.provenance.kind == ReferenceProvenanceKind::elf_relocation ? "ELF relocation"
                            : ref.provenance.kind == ReferenceProvenanceKind::elf_vtable_slot ? "ELF vtable slot"
                            : ref.provenance.kind == ReferenceProvenanceKind::dataflow       ? "dataflow"
                                                                                             : "decoded");
        case 4:
            return ref.association ? location_text(*ref.association, image) : wxString{};
        case 5:
            return endpoint_context(*project, ref.source, image);
        case 6:
            if (auto target = std::get_if<Location>(&ref.target))
                return endpoint_context(*project, *target, image);
            return wxString("-");
        default:
            return wxString{};
        }
    });
    table_->fit_columns({0, 1, 5, 6});
    if (preference.selected) {
        const auto selected = std::find_if(rows_->rows.begin(), rows_->rows.end(), [&](const auto &reference) {
            return reference.id == *preference.selected;
        });
        if (selected != rows_->rows.end())
            table_->select_row(static_cast<std::size_t>(selected - rows_->rows.begin()));
        else preference.selected.reset();
    }
    update_detail();
    update_actions();
    previous_->Enable(preference.offset > 0);
    next_->Enable(rows_->next_offset.has_value());
    status_->SetLabel(wxString::Format("%zu of %llu references%s; ", rows_->rows.size(),
                                       static_cast<unsigned long long>(rows_->total),
                                       project_->references->complete() ? "" : " (partial index)") +
                      analysis_state_text(*project_));
}
} // namespace hexlab::desktop
