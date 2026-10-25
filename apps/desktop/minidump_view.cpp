#include "minidump_view.hpp"
#include <wx/notebook.h>
#include <wx/settings.h>
#include <wx/sizer.h>
#include <algorithm>
#include <span>

namespace hexlab::desktop {
namespace {
constexpr std::size_t thread_limit = 65536, register_limit = 128, prefix_limit = 1232;
wxString number(std::uint64_t value) { return wxString::Format("0x%llX", static_cast<unsigned long long>(value)); }
wxString decimal(std::uint64_t value) { return wxString::Format("%llu", static_cast<unsigned long long>(value)); }
wxString architecture(std::uint16_t value) {
    switch (value) { case 0: return "x86"; case 5: return "ARM32"; case 9: return "AMD64"; case 12: return "ARM64"; }
    return "unsupported (" + decimal(value) + ")";
}
wxString context_status(MinidumpContextStatus value) {
    switch (value) {
    case MinidumpContextStatus::decoded: return "decoded";
    case MinidumpContextStatus::partial: return "partial";
    case MinidumpContextStatus::not_captured: return "not captured";
    case MinidumpContextStatus::unsupported_architecture: return "unsupported architecture";
    case MinidumpContextStatus::architecture_mismatch: return "architecture mismatch";
    case MinidumpContextStatus::malformed: return "malformed";
    }
    return "unknown";
}
wxString available(bool value) { return value ? "valid" : "unavailable"; }
wxString clipped(std::string_view value) {
    return text(value.substr(0, 1024)) + (value.size() > 1024 ? " [truncated]" : "");
}
const MinidumpMetadata *metadata(const std::shared_ptr<const DocumentSnapshot> &document) {
    return document && document->metadata_view().minidump ? &*document->metadata_view().minidump : nullptr;
}
struct ContextRecord {
    const MinidumpContext *context = nullptr;
    const MinidumpThread *thread = nullptr;
    const MinidumpException *exception = nullptr;
    std::uint32_t size = 0, rva = 0, thread_id = 0;
    FileOffset record{};
};
std::optional<ContextRecord> record_at(const MinidumpMetadata &dump, std::size_t row) {
    if (dump.exception) {
        if (!row) {
            const auto &e = *dump.exception;
            return ContextRecord{e.context ? &*e.context : nullptr, nullptr, &e,
                                 e.context_size, e.context_rva, e.thread_id, e.record_file_offset};
        }
        --row;
    }
    if (row >= std::min(dump.threads.size(), thread_limit)) return {};
    const auto &t = dump.threads[row];
    return ContextRecord{t.context ? &*t.context : nullptr, &t, nullptr,
                         t.context_size, t.context_rva, t.id, t.record_file_offset};
}
std::optional<Location> source_location(const DocumentSnapshot &document, FileOffset at, std::uint64_t size) {
    if (!document.input_storage && !document.image) return {};
    const auto total = document.file_storage().size();
    if (!size || at.value >= total || size > total - at.value) return {};
    return Location{at};
}
std::optional<Location> mapped_location(const DocumentSnapshot &document, std::uint64_t value) {
    if (!document.image) return {};
    const Address address{document.image->layout().space.id, value};
    return document.image->to_file_offset(address) ? std::optional<Location>(address) : std::nullopt;
}
bool address_register(const MinidumpContext &context, const MinidumpRegister &reg) {
    if (!context.architecture_valid ||
        (context.status != MinidumpContextStatus::decoded && context.status != MinidumpContextStatus::partial)) return false;
    if (context.byte_order != ByteOrder::little || reg.bytes.size() != reg.width / 8 ||
        (reg.width == 32 && reg.value > UINT32_MAX)) return false;
    const auto &n = reg.name;
    switch (context.processor_architecture) {
    case 0: return reg.width == 32 && context.control_valid && (n == "eip" || n == "esp" || n == "ebp");
    case 9: return reg.width == 64 && (((n == "rip" || n == "rsp") && context.control_valid) || (n == "rbp" && context.integer_valid));
    case 5: return reg.width == 32 && context.control_valid && (n == "pc" || n == "sp" || n == "lr");
    case 12: return reg.width == 64 && context.control_valid && (n == "pc" || n == "sp" || n == "x29" || n == "x30");
    default: return false;
    }
}
wxString register_value(const MinidumpRegister &reg) {
    if (reg.width <= 64) return number(reg.value);
    wxString result = "0x";
    const auto bytes = std::span(reg.bytes).first(std::min<std::size_t>(reg.bytes.size(), 16));
    for (std::size_t i = bytes.size(); i > 0; --i)
        result += wxString::Format("%02X", std::to_integer<unsigned>(bytes[i - 1]));
    return result;
}
} // namespace

MinidumpView::MinidumpView(wxWindow *parent) : wxPanel(parent) {
    SetName("minidump-view");
    auto *box = new wxBoxSizer(wxVERTICAL);
    status_ = new wxStaticText(this, wxID_ANY, "No Minidump metadata");
    status_->SetName("minidump-status");
    contexts_ = new VirtualTable(this, "minidump-contexts",
        {"Record", "Thread", "Context status", "Architecture", "Context file / size", "Requested / decoded", "Stack / exception address"});
    contexts_->SetMinSize(FromDIP(wxSize(-1, 160)));
    auto *tabs = new wxNotebook(this, wxID_ANY);
    auto *register_page = new wxPanel(tabs);
    auto *register_box = new wxBoxSizer(wxVERTICAL);
    register_status_ = new wxStaticText(register_page, wxID_ANY, "Select a context");
    registers_ = new VirtualTable(register_page, "minidump-registers",
        {"Register", "Bits", "Value", "Exact bytes (file order)", "Source file", "Mapped address"});
    register_go_ = new wxButton(register_page, wxID_ANY, "Go to mapped register");
    register_bytes_ = new wxButton(register_page, wxID_ANY, "Go to register bytes");
    register_go_->SetName("minidump-register-go"); register_bytes_->SetName("minidump-register-bytes");
    register_go_->SetToolTip("Available for valid instruction, stack, frame and link registers pointing into captured memory.");
    register_bytes_->SetToolTip("Open the exact captured register bytes in the dump file.");
    auto *register_buttons = new wxBoxSizer(wxHORIZONTAL);
    register_buttons->Add(register_go_, 0, wxALL, 4); register_buttons->Add(register_bytes_, 0, wxALL, 4);
    register_box->Add(register_status_, 0, wxEXPAND | wxALL, 4);
    register_box->Add(registers_, 1, wxEXPAND); register_box->Add(register_buttons, 0, wxEXPAND);
    register_page->SetSizer(register_box);
    auto *detail_page = new wxPanel(tabs);
    auto *detail_box = new wxBoxSizer(wxVERTICAL);
    details_ = new wxTextCtrl(detail_page, wxID_ANY, "", wxDefaultPosition, wxDefaultSize,
                              wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    details_->SetName("minidump-context-details");
    details_->SetFont(wxSystemSettings::GetFont(wxSYS_ANSI_FIXED_FONT));
    context_bytes_ = new wxButton(detail_page, wxID_ANY, "Go to context bytes");
    record_go_ = new wxButton(detail_page, wxID_ANY, "Go to stack / exception address");
    context_bytes_->SetName("minidump-context-bytes"); record_go_->SetName("minidump-record-go");
    context_bytes_->SetToolTip("Open the original context descriptor's file extent.");
    record_go_->SetToolTip("Available when the selected stack or exception address maps into captured memory.");
    auto *detail_buttons = new wxBoxSizer(wxHORIZONTAL);
    detail_buttons->Add(context_bytes_, 0, wxALL, 4); detail_buttons->Add(record_go_, 0, wxALL, 4);
    detail_box->Add(details_, 1, wxEXPAND); detail_box->Add(detail_buttons, 0, wxEXPAND);
    detail_page->SetSizer(detail_box);
    tabs->AddPage(register_page, "Registers"); tabs->AddPage(detail_page, "Context bytes and provenance");
    box->Add(status_, 0, wxEXPAND | wxALL, 4); box->Add(contexts_, 1, wxEXPAND);
    box->Add(tabs, 2, wxEXPAND | wxTOP, 4); SetSizer(box);
    contexts_->activate = [this](std::size_t row) { select_context(row); };
    registers_->activate = [this](std::size_t row) { select_register(row); };
    const auto bind_go = [this](wxButton *button, std::optional<Location> *target) {
        button->Bind(wxEVT_BUTTON, [this, target](wxCommandEvent &) { if (*target && navigate) navigate(**target); });
    };
    bind_go(register_go_, &register_target_); bind_go(register_bytes_, &register_source_);
    bind_go(context_bytes_, &context_source_); bind_go(record_go_, &record_target_);
    set_document({});
}

void MinidumpView::set_document(std::shared_ptr<const DocumentSnapshot> document) {
    if (document_ && document_ == document) return;
    document_ = std::move(document); context_row_.reset();
    register_target_.reset(); register_source_.reset(); context_source_.reset(); record_target_.reset();
    for (auto *button : {register_go_, register_bytes_, context_bytes_, record_go_}) button->Enable(false);
    contexts_->populate(0, {}); registers_->populate(0, {}); details_->ChangeValue({});
    register_status_->SetLabel("Select a context");
    const auto *dump = metadata(document_);
    if (!dump) { status_->SetLabel("No Minidump metadata in this document"); return; }
    const auto threads = std::min(dump->threads.size(), thread_limit);
    status_->SetLabel(architecture(dump->processor_architecture) + ": " + decimal(dump->threads.size()) +
        " threads; exception " + (dump->exception ? "present" : "absent") +
        "; metadata " + (document_->metadata_complete ? "complete" : "partial") +
        (threads < dump->threads.size() ? "; thread preview limited to 65536" : ""));
    const auto count = threads + (dump->exception ? 1u : 0u);
    contexts_->populate(count, [this](std::size_t row, int column) { return context_cell(row, column); });
    contexts_->fit_columns({0, 1, 2, 3, 4, 5, 6});
    if (count) { contexts_->select_row(0); select_context(0); }
    else {
        wxString notes = "No thread or exception context descriptors.\n";
        for (std::size_t i = 0; i < std::min<std::size_t>(dump->diagnostics.size(), 16); ++i)
            notes += "Dump note: " + clipped(dump->diagnostics[i]) + "\n";
        if (dump->diagnostics.size() > 16) notes += "Additional dump notes omitted\n";
        details_->ChangeValue(notes);
    }
}

wxString MinidumpView::context_cell(std::size_t row, int column) const {
    const auto *dump = metadata(document_); if (!dump) return {};
    const auto item = record_at(*dump, row); if (!item) return {};
    const auto *c = item->context;
    switch (column) {
    case 0: return item->exception ? "Exception" : "Thread";
    case 1: return decimal(item->thread_id);
    case 2: return c ? context_status(c->status)
        : item->size ? wxString("not decoded (limit)") : wxString("not captured");
    case 3: return architecture(c ? c->processor_architecture : dump->processor_architecture);
    case 4: return number(item->rva) + " / " + decimal(item->size);
    case 5: return c ? number(c->requested_groups) + " / " + number(c->decoded_groups) : wxString{};
    case 6: return item->exception ? number(item->exception->address) : number(item->thread->stack_address) + " + " + number(item->thread->stack_size);
    default: return {};
    }
}

const MinidumpContext *MinidumpView::selected_context() const {
    const auto *dump = metadata(document_); if (!dump || !context_row_) return nullptr;
    const auto item = record_at(*dump, *context_row_); return item ? item->context : nullptr;
}

void MinidumpView::select_context(std::size_t row) {
    const auto *dump = metadata(document_); if (!dump) return;
    const auto item = record_at(*dump, row); if (!item) return;
    context_row_ = row;
    register_target_.reset(); register_source_.reset(); context_source_.reset(); record_target_.reset();
    register_go_->Enable(false); register_bytes_->Enable(false);
    context_source_ = source_location(*document_, FileOffset{item->rva}, item->size);
    if (item->exception || item->thread->stack_size)
        record_target_ = mapped_location(*document_, item->exception ? item->exception->address : item->thread->stack_address);
    context_bytes_->Enable(context_source_.has_value()); record_go_->Enable(record_target_.has_value());
    wxString description = context_cell(row, 0) + " thread " + decimal(item->thread_id) +
        "\nRecord file: " + number(item->record.value) + "\nContext file: " + number(item->rva) +
        "; original size: " + decimal(item->size) + " bytes\n";
    if (item->exception) description += "Exception code: " + number(item->exception->code) +
        "; flags: " + number(item->exception->flags) + "; address: " + number(item->exception->address) + "\n";
    else description += "Stack: " + number(item->thread->stack_address) + " + " + number(item->thread->stack_size) +
        "; file: " + number(item->thread->stack_rva) + "; TEB: " + number(item->thread->teb) + "\n";
    const auto *c = item->context;
    if (c) {
        description += "Status: " + context_status(c->status) + "; architecture: " + architecture(c->processor_architecture) +
            "; architecture check: " + available(c->architecture_valid) + "\nContextFlags: " + number(c->flags) +
            "; requested groups: " + number(c->requested_groups) + "; decoded groups: " + number(c->decoded_groups) +
            "\nControl: " + available(c->control_valid) + "; integer: " + available(c->integer_valid) +
            "; segments: " + available(c->segments_valid) + "; debug: " + available(c->debug_valid) +
            "\nFloating: " + available(c->floating_valid) + "; ARM64 low/high: " + available(c->floating_low_valid) +
            "/" + available(c->floating_high_valid) + "; byte order: " + (c->byte_order == ByteOrder::little ? "little" : "big") + "\n";
        for (std::size_t i = 0; i < std::min<std::size_t>(c->diagnostics.size(), 32); ++i)
            description += "Context note: " + clipped(c->diagnostics[i]) + "\n";
        if (c->diagnostics.size() > 32) description += "Additional context notes omitted\n";
        const auto bytes = std::span(c->captured_prefix).first(std::min(c->captured_prefix.size(), prefix_limit));
        description += "\nCaptured prefix: " + decimal(c->captured_prefix.size()) + " of " + decimal(c->source_size) + " bytes\n";
        for (std::size_t offset = 0; offset < bytes.size(); offset += 16)
            description += number(std::uint64_t{c->source_rva} + offset) + ": " + hex_bytes(bytes.subspan(offset, std::min<std::size_t>(16, bytes.size() - offset))) + "\n";
        if (c->captured_prefix.size() > bytes.size()) description += "Additional captured bytes omitted\n";
    } else description += item->size ? "Context was not decoded; source descriptor retained (decode limit).\n" : "No captured context.\n";
    for (std::size_t i = 0; i < std::min<std::size_t>(dump->diagnostics.size(), 16); ++i)
        description += "Dump note: " + clipped(dump->diagnostics[i]) + "\n";
    if (dump->diagnostics.size() > 16) description += "Additional dump notes omitted\n";
    details_->ChangeValue(description); details_->SetInsertionPoint(0);
    const auto count = c ? std::min(c->registers.size(), register_limit) : 0;
    register_status_->SetLabel(c ? decimal(c->registers.size()) + " registers; " + context_status(c->status) +
        (count < c->registers.size() ? wxString("; preview limited to 128") : wxString{}) : wxString("No decoded registers"));
    registers_->populate(count, [this](std::size_t index, int column) -> wxString {
        const auto *context = selected_context();
        if (!context || index >= std::min(context->registers.size(), register_limit)) return {};
        const auto &reg = context->registers[index];
        switch (column) {
        case 0: return clipped(reg.name);
        case 1: return decimal(reg.width);
        case 2: return register_value(reg);
        case 3: return hex_bytes(std::span(reg.bytes).first(std::min<std::size_t>(reg.bytes.size(), 16)));
        case 4: return number(reg.file_offset.value);
        case 5: return address_register(*context, reg) && mapped_location(*document_, reg.value) ? number(reg.value) : wxString{};
        default: return {};
        }
    });
    registers_->fit_columns({0, 1, 2, 3, 4, 5});
}

void MinidumpView::select_register(std::size_t row) {
    register_target_.reset(); register_source_.reset();
    const auto *c = selected_context();
    if (c && row < std::min(c->registers.size(), register_limit)) {
        const auto &reg = c->registers[row];
        if (address_register(*c, reg)) register_target_ = mapped_location(*document_, reg.value);
        register_source_ = source_location(*document_, reg.file_offset, reg.bytes.size());
    }
    register_go_->Enable(register_target_.has_value()); register_bytes_->Enable(register_source_.has_value());
}
} // namespace hexlab::desktop
