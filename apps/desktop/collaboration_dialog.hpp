#pragma once

#include "hexlab/database/collaboration.hpp"
#include "hexlab/workspace/navigation.hpp"
#include <wx/dialog.h>
#include <wx/listbox.h>
#include <wx/textctrl.h>
#include <wx/button.h>
#include <wx/msgdlg.h>
#include <wx/stattext.h>
#include <wx/sizer.h>
#include <wx/timer.h>
#include <algorithm>
#include <functional>

namespace hexlab::desktop {

// Proposal review is deliberately a separate database client. The ProjectActor
// keeps ownership of its own SQL connection; this facade serializes the
// collaboration inbox and commits through the documented collaboration API.
class CollaborationDialog final : public wxDialog {
public:
    CollaborationDialog(wxWindow* parent, std::filesystem::path project_path,
                        std::function<bool()> synchronize = {},
                        std::function<void()> committed = {})
        : wxDialog(parent, wxID_ANY, "Collaboration Proposals", wxDefaultPosition,
                   wxSize(780, 520), wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER),
          path_(std::move(project_path)), synchronize_(std::move(synchronize)),
          committed_(std::move(committed)), peer_timer_(this) {
        auto* root = new wxBoxSizer(wxVERTICAL);
        root->Add(new wxStaticText(this, wxID_ANY,
            "Pending edits shared through this project file. Refresh before resolving to review the current project revision."),
            0, wxEXPAND | wxALL, 10);
        auto* body = new wxBoxSizer(wxHORIZONTAL);
        rows_ = new wxListBox(this, wxID_ANY);
        rows_->SetMinSize(wxSize(230, -1));
        detail_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize,
                                  wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
        body->Add(rows_, 0, wxEXPAND | wxLEFT | wxBOTTOM, 10);
        body->Add(detail_, 1, wxEXPAND | wxALL, 10);
        root->Add(body, 1, wxEXPAND);
        auto* actions = new wxBoxSizer(wxHORIZONTAL);
        refresh_ = new wxButton(this, wxID_REFRESH, "Refresh Shared State");
        accept_ = new wxButton(this, wxID_ANY, "Accept / Rebase");
        dismiss_ = new wxButton(this, wxID_ANY, "Dismiss Proposal");
        actions->Add(refresh_, 0, wxRIGHT, 8);
        actions->AddStretchSpacer();
        actions->Add(accept_, 0, wxRIGHT, 8);
        actions->Add(dismiss_, 0, wxRIGHT, 8);
        actions->Add(new wxButton(this, wxID_CANCEL, "Close"));
        root->Add(actions, 0, wxEXPAND | wxALL, 10);
        SetSizer(root);
        rows_->Bind(wxEVT_LISTBOX, [this](wxCommandEvent&) { show_selected(); });
        refresh_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { refresh(); });
        accept_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { accept_selected(); });
        dismiss_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { dismiss_selected(); });
        Bind(wxEVT_TIMER, [this](wxTimerEvent&) { poll_peer_state(); }, peer_timer_.GetId());
        load_facade();
    }

private:
    std::filesystem::path path_;
    std::function<bool()> synchronize_;
    std::function<void()> committed_;
    std::shared_ptr<database::ProjectCollaboration> collaboration_;
    std::shared_ptr<const database::ProjectState> head_;
    std::vector<database::CollaborationConflict> conflicts_;
    wxListBox* rows_ = nullptr;
    wxTextCtrl* detail_ = nullptr;
    wxButton *refresh_ = nullptr, *accept_ = nullptr, *dismiss_ = nullptr;
    wxTimer peer_timer_;
    std::optional<std::uint64_t> peer_version_;

    static wxString message(const std::string& value) { return wxString::FromUTF8(value.c_str()); }
    static wxString address_label(Address value) {
        return message(format_location(Location{value}));
    }
    static wxString patch_summary(std::span<const PatchSpan> spans) {
        if (spans.empty()) return "absent (no patch spans)";
        wxString result;
        constexpr std::size_t span_limit = 32, byte_limit = 16;
        for (std::size_t i = 0; i < std::min(spans.size(), span_limit); ++i) {
            const auto& span = spans[i];
            result += wxString::Format("  file+0x%llx, %llu bytes: ",
                static_cast<unsigned long long>(span.begin.value),
                static_cast<unsigned long long>(span.replacement.size()));
            const auto count = std::min({span.original.size(), span.replacement.size(), byte_limit});
            for (std::size_t n = 0; n < count; ++n)
                result += wxString::Format("%02X>%02X%s",
                    std::to_integer<unsigned>(span.original[n]),
                    std::to_integer<unsigned>(span.replacement[n]), n + 1 == count ? "" : " ");
            if (span.replacement.size() > count)
                result += wxString::Format(" … (+%llu bytes)",
                    static_cast<unsigned long long>(span.replacement.size() - count));
            result += "\n";
        }
        if (spans.size() > span_limit)
            result += wxString::Format("  … %llu additional spans\n",
                static_cast<unsigned long long>(spans.size() - span_limit));
        return result;
    }
    static wxString chunks_summary(const std::vector<DecisionRange>& chunks) {
        if (chunks.empty()) return "none";
        wxString result;
        constexpr std::size_t limit = 64;
        for (std::size_t i = 0; i < std::min(chunks.size(), limit); ++i)
            result += wxString::Format("%s + 0x%llx%s", address_label(chunks[i].begin),
                static_cast<unsigned long long>(chunks[i].size), i + 1 == std::min(chunks.size(), limit) ? "" : ", ");
        if (chunks.size() > limit) result += wxString::Format(" … (%llu more)", static_cast<unsigned long long>(chunks.size() - limit));
        return result;
    }
    static wxString type_description(const std::optional<database::TypeDefinition>& value) {
        if (!value) return "absent";
        return wxString::Format("#%llu '%s': %s",
            static_cast<unsigned long long>(value->id), message(value->name),
            value->type ? message(types::format(*value->type)) : wxString("<no type>"));
    }
    void show_error(const Error& error) {
        wxMessageBox(message(error.message), "Collaboration", wxOK | wxICON_ERROR, this);
    }
    bool load_facade() {
        auto opened = database::ProjectCollaboration::open(path_, {});
        if (!opened) { show_error(opened.error()); return false; }
        collaboration_ = std::move(opened.value());
        if (!refresh()) return false;
        peer_timer_.Start(1000);
        return true;
    }
    bool refresh(bool report_errors = true) {
        if (!collaboration_) return false;
        auto peer_version = collaboration_->external_change_version({});
        if (!peer_version) { if (report_errors) show_error(peer_version.error()); return false; }
        auto state = collaboration_->refresh({});
        if (!state) { if (report_errors) show_error(state.error()); return false; }
        auto pending = collaboration_->conflicts(false, {});
        if (!pending) { if (report_errors) show_error(pending.error()); return false; }
        // Remember the version sampled before reading project state and the
        // inbox. A concurrent commit during refresh is detected next tick.
        peer_version_ = peer_version.value();
        head_ = std::move(state.value());
        conflicts_ = std::move(pending.value());
        rows_->Clear();
        for (const auto& row : conflicts_)
            rows_->Append(wxString::Format("Proposal #%llu  (r%llu → r%llu)",
                static_cast<unsigned long long>(row.id),
                static_cast<unsigned long long>(row.base_revision),
                static_cast<unsigned long long>(row.observed_revision)));
        if (!conflicts_.empty()) rows_->SetSelection(0);
        show_selected();
        return true;
    }
    void poll_peer_state() {
        if (!collaboration_) return;
        auto version = collaboration_->external_change_version({});
        if (!version || (peer_version_ && version.value() == *peer_version_)) return;
        // Periodic peer refreshes stay quiet on transient I/O failures; the
        // unchanged token causes another attempt on the next timer tick.
        refresh(false);
    }
    void show_selected() {
        const int selected = rows_->GetSelection();
        if (selected == wxNOT_FOUND || static_cast<std::size_t>(selected) >= conflicts_.size()) {
            detail_->SetValue("No pending proposals. This window checks for shared edits automatically.");
            accept_->Disable(); dismiss_->Disable(); return;
        }
        const auto& conflict = conflicts_[static_cast<std::size_t>(selected)];
        wxString text;
        text += wxString::Format("Proposal #%llu\nBased on revision: %llu\nObserved revision: %llu\nCurrent revision: %llu\n\n",
            static_cast<unsigned long long>(conflict.id),
            static_cast<unsigned long long>(conflict.base_revision),
            static_cast<unsigned long long>(conflict.observed_revision),
            static_cast<unsigned long long>(head_ ? head_->revisions.edit : 0));
        text += wxString::Format("Changes: %llu\n\n", static_cast<unsigned long long>(conflict.proposal.changes.size()));
        bool supported = true;
        for (std::size_t i = 0; i < conflict.proposal.changes.size(); ++i) {
            text += wxString::Format("Change %llu\n", static_cast<unsigned long long>(i + 1));
            const auto& change = conflict.proposal.changes[i];
            if (const auto* a = std::get_if<database::AnnotationChange>(&change)) {
                if (!a->before && !a->after) { text += "Malformed annotation change has no base or proposal.\n\n"; supported = false; continue; }
                const auto location = a->before ? a->before->location : a->after->location;
                if (a->before && a->after && (a->before->id != a->after->id || a->before->location != a->after->location)) {
                    text += "  Unsupported identity/location change; this proposal cannot be rebased here.\n";
                    supported = false;
                    continue;
                }
                const auto current = std::find_if(head_->user->annotations.begin(), head_->user->annotations.end(), [&](const auto& row) {
                    return a->before ? row.id == a->before->id : row.location == location;
                });
                text += wxString::Format("Annotation at %s\n", message(format_location(location)));
                if (a->before) text += wxString::Format("  Base: name '%s', comment '%s'\n", message(a->before->name), message(a->before->comment));
                else text += "  Base: absent\n";
                if (a->after) text += wxString::Format("  Proposed: name '%s', comment '%s'\n", message(a->after->name), message(a->after->comment));
                else text += "  Proposed: deleted\n";
                if (current != head_->user->annotations.end()) text += wxString::Format("  Current: name '%s', comment '%s'\n", message(current->name), message(current->comment));
                else text += "  Current: absent\n";
                if (a->before && a->after && current != head_->user->annotations.end() &&
                    ((a->after->name != a->before->name && current->name != a->before->name && current->name != a->after->name) ||
                     (a->after->comment != a->before->comment && current->comment != a->before->comment && current->comment != a->after->comment)))
                    text += "  Rebase note: at least one field changed on both sides; accepting uses the proposed field value.\n";
            } else if (const auto* b = std::get_if<database::BookmarkChange>(&change)) {
                if (!b->before && !b->after) { text += "Malformed bookmark change has no base or proposal.\n\n"; supported = false; continue; }
                const auto location = b->before ? b->before->location : b->after->location;
                if (b->before && b->after && (b->before->id != b->after->id || b->before->location != b->after->location)) {
                    text += "  Unsupported identity/location change; this proposal cannot be rebased here.\n";
                    supported = false;
                    continue;
                }
                const auto current = std::find_if(head_->user->bookmarks.begin(), head_->user->bookmarks.end(), [&](const auto& row) {
                    return b->before ? row.id == b->before->id : row.location == location;
                });
                text += wxString::Format("Bookmark at %s\n", message(format_location(location)));
                if (b->before) text += wxString::Format("  Base: label '%s'\n", message(b->before->label));
                else text += "  Base: absent\n";
                if (b->after) text += wxString::Format("  Proposed: label '%s'\n", message(b->after->label));
                else text += "  Proposed: deleted\n";
                if (current != head_->user->bookmarks.end()) text += wxString::Format("  Current: label '%s'\n", message(current->label));
                else text += "  Current: absent\n";
                if (b->before && b->after && current != head_->user->bookmarks.end() &&
                    b->after->label != b->before->label && current->label != b->before->label && current->label != b->after->label)
                    text += "  Rebase note: the label changed on both sides; accepting uses the proposed label.\n";
            } else if (const auto* assignment = std::get_if<database::TypeAssignmentChange>(&change)) {
                if (!assignment->before && !assignment->after) {
                    text += "Malformed type-assignment change has no base or proposal.\n";
                    supported = false;
                    continue;
                }
                const auto& identity = assignment->before ? *assignment->before : *assignment->after;
                auto describe_type = [&](std::optional<std::uint64_t> type_id) {
                    if (!type_id) return wxString("absent");
                    const auto found = std::find_if(head_->user->types.begin(), head_->user->types.end(),
                        [&](const auto& type) { return type.id == *type_id; });
                    return found == head_->user->types.end()
                        ? wxString::Format("unknown type #%llu", static_cast<unsigned long long>(*type_id))
                        : message(found->name);
                };
                const auto current = std::find_if(head_->user->type_assignments.begin(), head_->user->type_assignments.end(),
                    [&](const auto& row) { return assignment->before ? row.id == assignment->before->id : row.location == identity.location; });
                text += wxString::Format("Type assignment at %s\n", message(format_location(identity.location)));
                text += "  Base: " + describe_type(assignment->before ? std::optional<std::uint64_t>{assignment->before->type_id} : std::nullopt) + "\n";
                text += "  Proposed: " + describe_type(assignment->after ? std::optional<std::uint64_t>{assignment->after->type_id} : std::nullopt) + "\n";
                if (current == head_->user->type_assignments.end()) text += "  Current: absent\n";
                else text += wxString("  Current: ") + describe_type(current->type_id) + "\n";
                if (assignment->before && assignment->after &&
                    (assignment->before->id != assignment->after->id || assignment->before->location != assignment->after->location)) {
                    text += "  Unsupported identity/location change; this proposal cannot be rebased here.\n";
                    supported = false;
                } else if (assignment->before && current != head_->user->type_assignments.end() && *current != *assignment->before &&
                           assignment->after && current->type_id != assignment->after->type_id) {
                    text += "  Rebase note: the assignment changed on both sides; accepting uses the proposed type.\n";
                } else if (assignment->before && current == head_->user->type_assignments.end() && assignment->after) {
                    text += "  Cannot safely accept: the base assignment was removed from the current project.\n";
                    supported = false;
                } else if (assignment->after && std::none_of(head_->user->types.begin(), head_->user->types.end(),
                               [&](const auto& type) { return type.id == assignment->after->type_id; })) {
                    text += "  Cannot accept: the proposed type definition is missing.\n";
                    supported = false;
                }
            } else if (const auto* region = std::get_if<database::RegionChange>(&change)) {
                if (!region->before && !region->after) { text += "Malformed region change has no base or proposal.\n"; supported = false; continue; }
                const auto& identity = region->before ? *region->before : *region->after;
                const auto current = std::find_if(head_->user->decisions.regions.begin(), head_->user->decisions.regions.end(),
                    [&](const auto& row) { return region->before ? row.id == identity.id : row.begin == identity.begin; });
                auto describe = [&](const std::optional<RegionDecision>& value) {
                    return value ? wxString::Format("%s + 0x%llx (%s)", address_label(value->begin),
                        static_cast<unsigned long long>(value->size), value->kind == RegionKind::code ? "code" : "data") : wxString("absent");
                };
                text += "Region decision\n  Base: " + describe(region->before) + "\n  Proposed: " + describe(region->after) + "\n";
                text += "  Current: " + describe(current == head_->user->decisions.regions.end() ? std::optional<RegionDecision>{} : *current) + "\n";
            } else if (const auto* function = std::get_if<database::FunctionChange>(&change)) {
                if (!function->before && !function->after) { text += "Malformed function change has no base or proposal.\n"; supported = false; continue; }
                const auto& identity = function->before ? *function->before : *function->after;
                const auto current = std::find_if(head_->user->decisions.functions.begin(), head_->user->decisions.functions.end(),
                    [&](const auto& row) { return function->before ? row.id == identity.id : row.entry == identity.entry; });
                auto describe = [&](const std::optional<FunctionDecision>& value) {
                    return value ? wxString::Format("entry %s, %s, chunks [%s]", address_label(value->entry),
                        value->suppressed ? "suppressed" : "active", chunks_summary(value->chunks)) : wxString("absent");
                };
                text += "Function decision\n  Base: " + describe(function->before) + "\n  Proposed: " + describe(function->after) + "\n";
                text += "  Current: " + describe(current == head_->user->decisions.functions.end() ? std::optional<FunctionDecision>{} : *current) + "\n";
            } else if (const auto* reference = std::get_if<database::ReferenceChange>(&change)) {
                if (!reference->before && !reference->after) { text += "Malformed reference change has no base or proposal.\n"; supported = false; continue; }
                const auto& identity = reference->before ? *reference->before : *reference->after;
                const auto current = std::find_if(head_->user->decisions.references.begin(), head_->user->decisions.references.end(),
                    [&](const auto& row) { return reference->before ? row.id == identity.id : row.source == identity.source; });
                auto describe = [](const std::optional<UserReference>& value) {
                    if (!value) return wxString("absent");
                    static constexpr const char* names[] = {"code", "data", "call", "jump", "read", "write", "address"};
                    const auto kind = static_cast<unsigned>(value->kind);
                    return wxString::Format("%s -> %s (%s)", message(format_location(value->source)),
                        message(format_location(value->target)), kind < std::size(names) ? names[kind] : "unknown");
                };
                text += "Explicit reference\n  Base: " + describe(reference->before) + "\n  Proposed: " + describe(reference->after) + "\n";
                text += "  Current: " + describe(current == head_->user->decisions.references.end() ? std::optional<UserReference>{} : *current) + "\n";
            } else if (const auto* patch = std::get_if<database::PatchChange>(&change)) {
                text += "Patch spans\n  Base:\n" + patch_summary(patch->before) + "  Proposed:\n" + patch_summary(patch->after) + "  Current:\n" + patch_summary(head_->user->patches);
            } else if (const auto* definition = std::get_if<database::TypeDefinitionChange>(&change)) {
                if (!definition->before && !definition->after) { text += "Malformed type-definition change has no base or proposal.\n"; supported = false; continue; }
                const auto& identity = definition->before ? *definition->before : *definition->after;
                const auto current = std::find_if(head_->user->types.begin(), head_->user->types.end(),
                    [&](const auto& row) { return row.id == identity.id; });
                text += "Type definition\n  Base: " + type_description(definition->before) + "\n  Proposed: " + type_description(definition->after) + "\n";
                text += "  Current: " + type_description(current == head_->user->types.end() ? std::optional<database::TypeDefinition>{} : *current) + "\n";
            } else if (const auto* variable = std::get_if<database::DebugVariableChange>(&change)) {
                if (!variable->before && !variable->after) { text += "Malformed debug-variable change has no base or proposal.\n"; supported = false; continue; }
                const auto& identity = variable->before ? *variable->before : *variable->after;
                const auto current = std::find_if(head_->user->debug_variables.begin(), head_->user->debug_variables.end(),
                    [&](const auto& row) { return row.id == identity.id; });
                auto describe = [](const std::optional<database::DebugVariable>& value) {
                    if (!value) return wxString("absent");
                    return wxString::Format("%s in %s, type #%s, %llu location ranges",
                        message(value->name), address_label(value->function_entry),
                        value->type_id ? wxString::Format("%llu", static_cast<unsigned long long>(*value->type_id)) : wxString("none"),
                        static_cast<unsigned long long>(value->location_ranges.size()));
                };
                text += "Debug variable\n  Base: " + describe(variable->before) + "\n  Proposed: " + describe(variable->after) + "\n";
                text += "  Current: " + describe(current == head_->user->debug_variables.end() ? std::optional<database::DebugVariable>{} : *current) + "\n";
                supported = false;
            } else if (const auto* breakpoint = std::get_if<database::ProjectBreakpointChange>(&change)) {
                if (!breakpoint->before && !breakpoint->after) { text += "Malformed project-breakpoint change has no base or proposal.\n"; supported = false; continue; }
                const auto& identity = breakpoint->before ? *breakpoint->before : *breakpoint->after;
                const auto current = std::find_if(head_->user->breakpoints.begin(), head_->user->breakpoints.end(),
                    [&](const auto& row) { return row.id == identity.id; });
                auto describe = [](const std::optional<database::ProjectBreakpoint>& value) {
                    if (!value) return wxString("absent");
                    return wxString::Format("%s, kind %u, size %u, %s", address_label(value->address),
                        static_cast<unsigned>(value->kind), static_cast<unsigned>(value->size), value->enabled ? "enabled" : "disabled");
                };
                text += "Project breakpoint\n  Base: " + describe(breakpoint->before) + "\n  Proposed: " + describe(breakpoint->after) + "\n";
                text += "  Current: " + describe(current == head_->user->breakpoints.end() ? std::optional<database::ProjectBreakpoint>{} : *current) + "\n";
                supported = false;
            } else {
                text += "Unknown project change (requires domain-specific rebase)\n";
                supported = false;
            }
            text += "\n";
        }
        text += "Accept / Rebase previews the database's conservative three-way merge against the current project revision. It covers annotations, bookmarks, type definitions and assignments, analysis decisions, explicit references, and byte patches. Conflicting fields or bytes are never silently selected; unsupported structural edits remain pending for a domain-specific workflow.";
        bool can_resolve = false;
        if (supported && collaboration_ && head_) {
            auto preview = collaboration_->preview_resolution(conflict.id, head_->revisions.edit, {});
            can_resolve = preview && preview.value().has_value();
            if (!preview) text += "\n\nResolution preview unavailable: " + message(preview.error().message);
            else if (!preview.value()) text += "\n\nThis proposal has a structural or overlapping conflict that requires a domain-specific decision.";
        }
        detail_->SetValue(text);
        accept_->Enable(can_resolve);
        dismiss_->Enable(head_ != nullptr);
    }
    void accept_selected() {
        const int selected = rows_->GetSelection();
        if (selected == wxNOT_FOUND || !head_) return;
        const auto id = conflicts_[static_cast<std::size_t>(selected)].id;
        // Drain this document actor's already-submitted work before resolving;
        // otherwise an older local command could race the collaboration commit
        // and lose its edit-revision compare-and-swap.
        if (synchronize_ && !synchronize_()) return;
        // Re-read just before the commit so every before-value and CAS revision
        // belongs to the same refreshed project head.
        if (!refresh()) return;
        auto row = std::find_if(conflicts_.begin(), conflicts_.end(), [&](const auto& item) { return item.id == id; });
        if (row == conflicts_.end()) return;
        auto resolution = collaboration_->preview_resolution(row->id, head_->revisions.edit, {});
        if (!resolution) { show_error(resolution.error()); refresh(); return; }
        if (!resolution.value()) {
            wxMessageBox("This proposal overlaps another entity or contains data that cannot be safely rebased by this window.",
                         "Proposal needs manual resolution", wxOK | wxICON_WARNING, this);
            return;
        }
        auto resolved = collaboration_->resolve(row->id, true, head_->revisions.edit, *resolution.value(),
            static_cast<std::uint64_t>(wxGetUTCTimeMillis().GetValue()), {});
        if (!resolved) { show_error(resolved.error()); refresh(); return; }
        // Notify the open document only after SQLite confirms the proposal and
        // resolution were committed atomically.
        if (committed_) committed_();
        wxMessageBox("Proposal accepted and rebased onto the latest project revision.",
                     "Proposal accepted", wxOK | wxICON_INFORMATION, this);
        refresh();
    }
    void dismiss_selected() {
        const int selected = rows_->GetSelection();
        if (selected == wxNOT_FOUND || !head_) return;
        const auto id = conflicts_[static_cast<std::size_t>(selected)].id;
        if (synchronize_ && !synchronize_()) return;
        if (!refresh()) return;
        if (std::none_of(conflicts_.begin(), conflicts_.end(), [&](const auto& item) { return item.id == id; })) return;
        auto dismissed = collaboration_->dismiss(id, head_->revisions.edit, {});
        if (!dismissed) { show_error(dismissed.error()); refresh(); return; }
        wxMessageBox("Proposal dismissed. The current project state was kept.",
                     "Proposal dismissed", wxOK | wxICON_INFORMATION, this);
        refresh();
    }
};
} // namespace hexlab::desktop
