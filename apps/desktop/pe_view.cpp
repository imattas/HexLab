#include "pe_view.hpp"
#include "hexlab/workspace/project.hpp"
#include <wx/sizer.h>
#include <algorithm>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace hexlab::desktop {
namespace {
struct BoundRow {
    const PeBoundImport *module = nullptr;
    const PeBoundImportForwarder *forwarder = nullptr;
    std::optional<FileOffset> source;
};
struct ExceptionRow {
    std::optional<Address> address;
    std::string kind, detail;
    std::optional<FileOffset> source;
};
struct ResourceRow {
    const PeResource *resource = nullptr;
};
std::optional<FileOffset> source_offset(const PeRecordSource &source) {
    if (source.spans.empty()) return {};
    return source.spans.front().offset;
}
wxString resource_identifier(const PeResourceIdentifier &identifier) {
    if (identifier.name) return text(*identifier.name);
    if (identifier.id) return wxString::Format("#%04X", static_cast<unsigned>(*identifier.id));
    return "unavailable";
}
const char *certificate_type_name(std::uint16_t type) {
    switch (type) {
    case 1: return "X.509";
    case 2: return "PKCS#7 signed data";
    case 3: return "reserved type 3";
    case 4: return "TS stack signed";
    case 0x0ef0: return "EFI PKCS#1.5";
    case 0x0ef1: return "EFI GUID";
    case 0x0ef2: return "EFI PKCS#7";
    case 0x0ef3: return "EFI unauthenticated GUID";
    default: return "opaque type";
    }
}
} // namespace

PeView::PeView(wxWindow *parent) : wxPanel(parent) {
    auto *tabs = new wxNotebook(this, wxID_ANY);
    directories_ = new VirtualTable(tabs, "pe-directories", {"#", "Kind", "RVA / file", "Size"});
    auto *resource_page = new wxPanel(tabs);
    resource_status_ = new wxStaticText(resource_page, wxID_ANY, "Resources: unavailable");
    resources_ = new VirtualTable(resource_page, "pe-resources",
        {"Type", "Name", "Language", "RVA", "Size", "Code page", "Data entry", "Payload file",
         "Version strings", "Record"});
    auto *resource_layout = new wxBoxSizer(wxVERTICAL);
    resource_layout->Add(resource_status_, 0, wxEXPAND | wxALL, 4);
    resource_layout->Add(resources_, 1, wxEXPAND);
    resource_page->SetSizer(resource_layout);
    bound_imports_ = new VirtualTable(tabs, "pe-bound-imports", {"Source", "Library", "Timestamp", "Record"});
    auto *certificate_page = new wxPanel(tabs);
    certificate_status_ = new wxStaticText(certificate_page, wxID_ANY,
        "Certificate table: unavailable; signatures are not verified");
    certificates_ = new VirtualTable(certificate_page, "pe-certificates",
        {"File offset", "Length", "Revision", "Type", "Payload bytes", "Record"});
    auto *certificate_layout = new wxBoxSizer(wxVERTICAL);
    certificate_layout->Add(certificate_status_, 0, wxEXPAND | wxALL, 4);
    certificate_layout->Add(certificates_, 1, wxEXPAND);
    certificate_page->SetSizer(certificate_layout);
    auto *load_config_page = new wxPanel(tabs);
    load_config_status_ = new wxStaticText(load_config_page, wxID_ANY, "SafeSEH: unavailable");
    safe_seh_ = new VirtualTable(load_config_page, "pe-safe-seh", {"Handler RVA", "Source", "Record"});
    auto *load_config_layout = new wxBoxSizer(wxVERTICAL);
    load_config_layout->Add(load_config_status_, 0, wxEXPAND | wxALL, 4);
    load_config_layout->Add(safe_seh_, 1, wxEXPAND);
    load_config_page->SetSizer(load_config_layout);
    auto *runtime_view_page = new wxPanel(tabs);
    runtime_view_status_ = new wxStaticText(runtime_view_page, wxID_ANY,
        "ARM64X runtime views are unavailable for this image");
    open_arm64_view_ = new wxButton(runtime_view_page, wxID_ANY, "Open ARM64 process view in new tab");
    open_x64_view_ = new wxButton(runtime_view_page, wxID_ANY, "Open x64 / ARM64EC-compatible view in new tab");
    open_arm64_view_->SetName("pe-runtime-arm64");
    open_x64_view_->SetName("pe-runtime-x64-compatible");
    open_arm64_view_->Enable(false);
    open_x64_view_->Enable(false);
    open_arm64_view_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (open_runtime_view) open_runtime_view(PeRuntimeArchitecture::arm64);
    });
    open_x64_view_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (open_runtime_view) open_runtime_view(PeRuntimeArchitecture::x64_compatible);
    });
    auto *runtime_view_layout = new wxBoxSizer(wxVERTICAL);
    runtime_view_layout->Add(runtime_view_status_, 0, wxEXPAND | wxALL, 6);
    runtime_view_layout->Add(open_arm64_view_, 0, wxALL, 6);
    runtime_view_layout->Add(open_x64_view_, 0, wxALL, 6);
    runtime_view_page->SetSizer(runtime_view_layout);
    exceptions_ = new VirtualTable(tabs, "pe-exceptions", {"Address", "Record", "Details", "Source"});
    pdb_symbols_ = new VirtualTable(tabs, "pe-pdb-symbols", {"Address", "Kind", "Name", "Section", "Type index"});
    pdb_types_ = new VirtualTable(tabs, "pe-pdb-types", {"Index", "Kind", "Name", "Size"});
    pdb_lines_ = new VirtualTable(tabs, "pe-pdb-lines", {"Address", "Line", "Source", "Module"});
    pdb_inline_ = new VirtualTable(tabs, "pe-pdb-inline", {"Address", "Bytes", "Source", "Inlinee IPI", "Scope / origin", "State"});
    pdb_status_ = new wxStaticText(this, wxID_ANY, "PDB: unavailable");
    tabs->AddPage(directories_, "Data directories");
    tabs->AddPage(resource_page, "Resources");
    tabs->AddPage(bound_imports_, "Bound imports");
    tabs->AddPage(certificate_page, "Certificates");
    tabs->AddPage(load_config_page, "Load config");
    tabs->AddPage(runtime_view_page, "Runtime views");
    tabs->AddPage(exceptions_, "Exceptions / unwind");
    tabs->AddPage(pdb_symbols_, "PDB symbols");
    tabs->AddPage(pdb_types_, "PDB types");
    tabs->AddPage(pdb_lines_, "PDB lines");
    tabs->AddPage(pdb_inline_, "PDB inline scopes");
    auto *layout = new wxBoxSizer(wxVERTICAL);
    layout->Add(pdb_status_, 0, wxEXPAND | wxALL, 4);
    layout->Add(tabs, 1, wxEXPAND);
    SetSizer(layout);
    set_document({});
}

void PeView::set_document(std::shared_ptr<const DocumentSnapshot> document) {
    document_ = std::move(document);
    const auto *metadata = document_ ? &document_->metadata_view() : nullptr;
    const bool pe = metadata && metadata->pe.has_value();
    if (!pe) {
        directories_->populate(0, {});
        resource_status_->SetLabel("Resources: unavailable");
        resources_->populate(0, {});
        bound_imports_->populate(0, {});
        certificates_->populate(0, {});
        certificate_status_->SetLabel("Certificate table: unavailable; signatures are not verified");
        safe_seh_->populate(0, {});
        load_config_status_->SetLabel("SafeSEH: unavailable");
        runtime_view_status_->SetLabel("ARM64X runtime views are unavailable for this image");
        open_arm64_view_->Enable(false);
        open_x64_view_->Enable(false);
        exceptions_->populate(0, {});
        pdb_symbols_->populate(0, {}); pdb_types_->populate(0, {}); pdb_lines_->populate(0, {});
        pdb_inline_->populate(0, {}); pdb_inline_->activate = {};
        pdb_status_->SetLabel("PDB: unavailable");
        directories_->activate = {};
        resources_->activate = {};
        bound_imports_->activate = {};
        certificates_->activate = {};
        safe_seh_->activate = {};
        exceptions_->activate = {};
        return;
    }

    const auto directory_count = std::min<std::size_t>(metadata->directories.size(), 16);
    directories_->populate(directory_count, [this, metadata](std::size_t row, int column) {
        const auto &item = metadata->directories[row];
        switch (column) {
        case 0: return wxString::Format("%u", item.index);
        case 1: return wxString(item.file_offset ? "file offset" : "RVA");
        case 2: return wxString::Format("0x%08X", item.location);
        default: return wxString::Format("0x%X", item.size);
        }
    });
    directories_->activate = [this, metadata](std::size_t row) {
        if (!document_ || row >= metadata->directories.size()) return;
        const auto &entry = metadata->directories[row];
        if (entry.file_offset) {
            if (entry.location <= document_->image->storage()->size() && navigate)
                navigate(FileOffset{entry.location});
            return;
        }
        const auto base = metadata->preferred_base;
        if (entry.location <= UINT64_MAX - base)
            if (navigate) navigate(Address{{0}, base + entry.location});
    };

    constexpr std::size_t resource_display_limit = 4096;
    const auto &resource_records = metadata->pe->resources;
    std::vector<ResourceRow> resource_rows;
    resource_rows.reserve(std::min(resource_display_limit, resource_records.size()));
    for (const auto &resource : resource_records) {
        if (resource_rows.size() >= resource_display_limit) break;
        resource_rows.push_back({&resource});
    }
    resource_status_->SetLabel(wxString::Format(
        "Resources: %llu records%s; select a row to navigate to its file-backed payload",
        static_cast<unsigned long long>(resource_records.size()),
        resource_records.size() > resource_rows.size() ? " (display limited to 4096 rows)" : ""));
    resources_->populate(resource_rows.size(), [resource_rows](std::size_t row, int column) {
        if (row >= resource_rows.size() || !resource_rows[row].resource) return wxString{};
        const auto &item = *resource_rows[row].resource;
        switch (column) {
        case 0: return resource_identifier(item.type);
        case 1: return resource_identifier(item.name);
        case 2: return resource_identifier(item.language);
        case 3: return wxString::Format("0x%08X", item.data_rva);
        case 4: return wxString::Format("0x%X", item.size);
        case 5: return wxString::Format("0x%X", item.code_page);
        case 6:
            return item.data_entry.spans.empty() ? wxString("unavailable")
                : location_text(Location{item.data_entry.spans.front().offset});
        case 7:
            return item.payload.empty() ? wxString("unavailable")
                : location_text(Location{item.payload.front().offset});
        case 8: {
            if (!item.version_info) return wxString{};
            wxString summary;
            constexpr std::string_view shown[] = {
                "FileDescription", "CompanyName", "ProductName", "OriginalFilename", "InternalName"};
            for (const auto &entry : item.version_info->strings) {
                bool visible = false;
                for (const auto key : shown)
                    if (std::string_view(entry.key) == key) { visible = true; break; }
                if (!visible || entry.value.empty() || entry.value.size() > 512) continue;
                if (!summary.empty()) summary += "; ";
                summary += text(entry.key + "=" + entry.value);
                if (summary.length() >= 512) {
                    summary = summary.Left(512);
                    summary += "...";
                    break;
                }
            }
            return summary;
        }
        default: return wxString::Format("%u", item.data_entry.index);
        }
    });
    resources_->activate = [this, resource_rows](std::size_t row) {
        if (row >= resource_rows.size() || !resource_rows[row].resource || !navigate) return;
        const auto &item = *resource_rows[row].resource;
        if (item.size != 0 && !item.payload.empty())
            navigate(Location{item.payload.front().offset});
    };

    std::vector<BoundRow> rows;
    rows.reserve(std::min<std::size_t>(4096, metadata->pe->bound_imports.size() * 2));
    for (const auto &item : metadata->pe->bound_imports) {
        if (rows.size() >= 4096) break;
        rows.push_back({&item, nullptr, source_offset(item.descriptor)});
        for (const auto &forwarder : item.forwarders) {
            if (rows.size() >= 4096) break;
            rows.push_back({&item, &forwarder, source_offset(forwarder.descriptor)});
        }
    }
    bound_imports_->populate(rows.size(), [rows](std::size_t row, int column) {
        const auto &item = rows[row];
        const auto library = item.forwarder ? item.forwarder->library : item.module->library;
        const auto timestamp = item.forwarder ? item.forwarder->timestamp : item.module->timestamp;
        switch (column) {
        case 0: return item.source ? location_text(*item.source) : wxString("unavailable");
        case 1: return (item.forwarder ? wxString("  ↳ ") : wxString{}) + text(library);
        case 2: return wxString::Format("0x%08X", timestamp);
        default: return item.forwarder ? wxString("forwarder") : wxString("module");
        }
    });
    bound_imports_->activate = [this, rows](std::size_t row) {
        if (row < rows.size() && rows[row].source && navigate)
            navigate(*rows[row].source);
    };
    const auto &certificate_table = metadata->pe->certificate_table;
    if (!certificate_table) {
        certificate_status_->SetLabel("Certificate table: not present; signatures are not verified");
        certificates_->populate(0, {});
        certificates_->activate = {};
    } else {
        constexpr std::size_t certificate_display_limit = 4096;
        const auto &records = certificate_table->records;
        const auto shown = std::min(certificate_display_limit, records.size());
        certificate_status_->SetLabel(wxString::Format(
            "Certificate table: %u records at file offset 0x%llX, size 0x%X; payloads are opaque and signatures are not verified%s",
            static_cast<unsigned>(records.size()),
            static_cast<unsigned long long>(certificate_table->file_offset.value),
            certificate_table->size, shown < records.size() ? " (display limited to 4096 rows)" : ""));
        certificates_->populate(shown, [records, shown](std::size_t row, int column) {
            (void)shown;
            const auto &record = records[row];
            const auto offset = record.source.spans.empty() ? 0 : record.source.spans.front().offset.value;
            const auto payload_size = record.payload.empty() ? 0 : record.payload.front().size;
            switch (column) {
            case 0: return wxString::Format("0x%llX", static_cast<unsigned long long>(offset));
            case 1: return wxString::Format("0x%X", record.length);
            case 2: return wxString::Format("0x%04X", record.revision);
            case 3: return wxString::Format("0x%04X (%s)", record.type, certificate_type_name(record.type));
            case 4: return wxString::Format("0x%llX", static_cast<unsigned long long>(payload_size));
            default: return wxString::Format("%u", record.source.index);
            }
        });
        certificates_->activate = [this, records, shown](std::size_t row) {
            if (row >= shown || !navigate) return;
            const auto &record = records[row];
            if (!record.payload.empty()) navigate(record.payload.front().offset);
            else if (!record.source.spans.empty()) navigate(record.source.spans.front().offset);
        };
    }
    const auto &load_config = metadata->pe->load_configuration;
    const auto loaded = document_->project ? document_->project->loaded : nullptr;
    const bool has_alternative = loaded && static_cast<bool>(loaded->pe_arm64x_image);
    const bool has_arm64x_records = load_config && load_config->dynamic_value_relocations &&
        std::any_of(load_config->dynamic_value_relocations->records.begin(),
                    load_config->dynamic_value_relocations->records.end(),
                    [](const auto &record) { return record.symbol == 6; });
    if (has_alternative) {
        const wxString selected = loaded->pe_runtime_target
            ? (*loaded->pe_runtime_target == PeRuntimeArchitecture::arm64 ? "ARM64" : "x64-compatible")
            : "file-default";
        runtime_view_status_->SetLabel(wxString::Format(
            "ARM64X alternative is available (%llu fixups applied)",
            static_cast<unsigned long long>(load_config && load_config->dynamic_value_relocations
                ? load_config->dynamic_value_relocations->applied_fixups.size() : 0)) +
            "; current project view: " + selected);
        open_arm64_view_->Enable(true);
        open_x64_view_->Enable(true);
    } else {
        const auto status = has_arm64x_records
            ? "ARM64X records are present, but a complete alternate view could not be applied"
            : "No decoded ARM64X alternate process view is available";
        runtime_view_status_->SetLabel(status);
        open_arm64_view_->Enable(false);
        open_x64_view_->Enable(false);
    }
    if (!load_config || !load_config->safe_seh_table_rva) {
        load_config_status_->SetLabel("SafeSEH: not present");
        safe_seh_->populate(0, {});
        safe_seh_->activate = {};
    } else {
        load_config_status_->SetLabel(wxString::Format("SafeSEH: %llu handlers; table RVA 0x%llX",
            static_cast<unsigned long long>(load_config->safe_seh_handlers.size()),
            static_cast<unsigned long long>(*load_config->safe_seh_table_rva)));
        const auto handlers = load_config->safe_seh_handlers;
        safe_seh_->populate(handlers.size(), [handlers](std::size_t row, int column) {
            const auto &handler = handlers[row];
            switch (column) {
            case 0: return wxString::Format("0x%08X", handler.rva);
            case 1: return handler.source.spans.empty() ? wxString("unavailable") : location_text(handler.source.spans.front().offset);
            default: return wxString::Format("%u", handler.source.index);
            }
        });
        safe_seh_->activate = [this, metadata, handlers](std::size_t row) {
            if (row >= handlers.size() || !navigate) return;
            const auto base = metadata->preferred_base;
            if (handlers[row].rva <= UINT64_MAX - base)
                navigate(Address{{0}, base + handlers[row].rva});
        };
    }
    std::vector<ExceptionRow> exception_rows;
    constexpr std::size_t exception_row_limit = 4096;
    bool exception_rows_truncated = false;
    const auto add_exception_row = [&](std::optional<Address> address, std::string kind,
                                       std::string detail, const PeRecordSource &source) {
        if (exception_rows.size() + 1 < exception_row_limit) {
            exception_rows.push_back({address, std::move(kind), std::move(detail), source_offset(source)});
        } else if (!exception_rows_truncated) {
            exception_rows.push_back({{}, "display limit reached", "Additional exception rows were omitted.", {}});
            exception_rows_truncated = true;
        }
    };
    const auto rva_address = [metadata](std::uint32_t rva) -> std::optional<Address> {
        if (rva > UINT64_MAX - metadata->preferred_base) return {};
        return Address{{0}, metadata->preferred_base + rva};
    };
    for (const auto &function : metadata->pe->exception_functions) {
        if (exception_rows.size() >= exception_row_limit) break;
        add_exception_row(rva_address(function.begin_rva), "AMD64 runtime function",
            wxString::Format("end RVA 0x%08X; unwind RVA 0x%08X", function.end_rva,
                             function.unwind_info_rva).ToStdString(), function.source);
        if (!function.unwind_info) continue;
        const auto &unwind = *function.unwind_info;
        if (unwind.handler_payload) {
            const auto &payload = *unwind.handler_payload;
            const auto status = payload.status == PeHandlerPayloadStatus::decoded_c_specific_scope_table
                ? "C-specific scope table" : payload.status == PeHandlerPayloadStatus::decoded_cxx_func_info
                ? "C++ FuncInfo (partial)" : payload.status == PeHandlerPayloadStatus::unsupported_handler
                ? "unsupported handler payload" : "unresolved handler payload";
            const auto source = payload.source.value_or(unwind.source);
            add_exception_row(payload.handler_name ? rva_address(*unwind.handler_rva) : std::nullopt,
                status, (payload.handler_name ? *payload.handler_name : std::string("unknown")) +
                wxString::Format("; payload RVA 0x%08X", payload.payload_rva).ToStdString(), source);
            for (std::size_t i = 0; i < payload.c_specific_scopes.size() &&
                 exception_rows.size() < exception_row_limit; ++i) {
                const auto &scope = payload.c_specific_scopes[i];
                add_exception_row(rva_address(scope.begin_rva), "C-specific scope",
                    wxString::Format("end 0x%08X; handler 0x%08X; jump 0x%08X",
                        scope.end_rva, scope.handler_rva, scope.jump_target_rva).ToStdString(), scope.source);
            }
            if (payload.cxx_func_info) {
                const auto &info = *payload.cxx_func_info;
                add_exception_row(rva_address(payload.payload_rva), "C++ FuncInfo header",
                    wxString::Format("max state %d; unwind map RVA 0x%08X; try blocks %u; IP states %u",
                        info.max_state, info.unwind_map_rva, info.try_block_count, info.ip_map_count).ToStdString(), info.source);
                for (std::size_t i = 0; i < info.unwind_map.size() &&
                     exception_rows.size() < exception_row_limit; ++i) {
                    const auto &entry = info.unwind_map[i];
                    add_exception_row(entry.action_rva ? rva_address(entry.action_rva) : std::nullopt,
                        "C++ unwind state", wxString::Format("state %zu -> %d; action RVA 0x%08X",
                            i, entry.to_state, entry.action_rva).ToStdString(), entry.source);
                }
            }
        }
    }
    for (const auto &function : metadata->pe->arm64_exception_functions) {
        if (exception_rows.size() >= exception_row_limit) break;
        const auto kind = function.kind == PeArm64UnwindKind::xdata ? "ARM64 xdata runtime function" :
            function.kind == PeArm64UnwindKind::packed_single ? "ARM64 packed runtime function" :
            function.kind == PeArm64UnwindKind::packed_fragment ? "ARM64 packed fragment" : "ARM64 pdata link";
        const auto length = function.function_length;
        add_exception_row(rva_address(function.begin_rva), kind,
            wxString::Format("length 0x%X; linked RVA %s", length,
                function.linked_record_rva ? wxString::Format("0x%08X", *function.linked_record_rva) : wxString("none")).ToStdString(),
            function.source);
        if (function.xdata && function.xdata->handler_rva && exception_rows.size() < exception_row_limit)
            add_exception_row(rva_address(*function.xdata->handler_rva), "ARM64 exception handler",
                "language payload is retained as metadata", function.xdata->handler_source.value_or(function.xdata->source));
    }
    exceptions_->populate(exception_rows.size(), [exception_rows](std::size_t row, int column) {
        const auto &item = exception_rows[row];
        switch (column) {
        case 0: return item.address ? location_text(Location{*item.address}) : wxString("—");
        case 1: return text(item.kind);
        case 2: return text(item.detail);
        default: return item.source ? location_text(*item.source) : wxString("unavailable");
        }
    });
    exceptions_->activate = [this, exception_rows](std::size_t row) {
        if (row < exception_rows.size() && exception_rows[row].source && navigate)
            navigate(*exception_rows[row].source);
        else if (row < exception_rows.size() && exception_rows[row].address && navigate)
            navigate(*exception_rows[row].address);
    };
    const auto &pdb = *metadata->pe;
    const auto *pdb_ptr = &pdb;
    const char *status = pdb.pdb_status == PePdbStatus::matched ? "matched" :
                         pdb.pdb_status == PePdbStatus::missing ? "missing" :
                         pdb.pdb_status == PePdbStatus::mismatch ? "identity mismatch" :
                         pdb.pdb_status == PePdbStatus::malformed ? "malformed" : "unavailable";
    pdb_status_->SetLabel(wxString("PDB: ") + status + "  " + text(pdb.pdb_path) +
        wxString::Format("  (%llu symbols, %llu types, %llu source lines, %llu inline scopes; tables show up to 4096 rows)",
            static_cast<unsigned long long>(pdb.pdb_symbols.size()),
            static_cast<unsigned long long>(pdb.pdb_types.size()), static_cast<unsigned long long>(pdb.source_lines.size()),
            static_cast<unsigned long long>(pdb.pdb_inline_sites.size())));
    pdb_symbols_->populate(std::min<std::size_t>(4096, pdb.pdb_symbols.size()), [this, pdb_ptr](std::size_t row, int column) {
        const auto &item = pdb_ptr->pdb_symbols[row];
        switch (column) {
        case 0: return item.address ? location_text(Location{*item.address}) : wxString::Format("section %u+0x%X", item.section, item.section_offset);
        case 1: return item.procedure ? wxString("procedure") : wxString("data");
        case 2: return text(item.name);
        case 3: return wxString::Format("%u", item.section);
        default: return item.type_index ? wxString(item.type_index_is_id ? "IPI" : "TPI") +
                                               wxString::Format(" 0x%X", item.type_index) : wxString("unavailable");
        }
    });
    pdb_symbols_->activate = [this, pdb_ptr](std::size_t row) {
        if (row < pdb_ptr->pdb_symbols.size() && pdb_ptr->pdb_symbols[row].address && navigate) navigate(*pdb_ptr->pdb_symbols[row].address);
    };
    pdb_types_->populate(std::min<std::size_t>(4096, pdb.pdb_types.size()), [pdb_ptr](std::size_t row, int column) {
        const auto &item = pdb_ptr->pdb_types[row];
        switch (column) {
        case 0: return wxString::Format("0x%X", item.index);
        case 1: return wxString::Format("0x%04X", item.leaf);
        case 2: return text(item.name);
        default: return wxString::Format("%llu", static_cast<unsigned long long>(item.size));
        }
    });
    pdb_lines_->populate(std::min<std::size_t>(4096, pdb.source_lines.size()), [pdb_ptr](std::size_t row, int column) {
        const auto &item = pdb_ptr->source_lines[row];
        switch (column) {
        case 0: return item.address ? location_text(Location{*item.address}) : wxString("unmapped");
        case 1: return wxString::Format("%u", item.line);
        case 2: return text(item.source_path);
        default: return text(item.module_name);
        }
    });
    pdb_lines_->activate = [this, pdb_ptr](std::size_t row) {
        if (row < pdb_ptr->source_lines.size() && pdb_ptr->source_lines[row].address && navigate) navigate(*pdb_ptr->source_lines[row].address);
    };
    std::vector<std::pair<std::size_t, std::optional<std::size_t>>> inline_rows;
    for (std::size_t i = 0; i < pdb.pdb_inline_sites.size() && inline_rows.size() < 4096; ++i) {
        const auto &site = pdb.pdb_inline_sites[i];
        if (site.ranges.empty()) inline_rows.emplace_back(i, std::nullopt);
        for (std::size_t r = 0; r < site.ranges.size() && inline_rows.size() < 4096; ++r)
            inline_rows.emplace_back(i, r);
    }
    pdb_inline_->populate(inline_rows.size(), [pdb_ptr, inline_rows](std::size_t row, int column) {
        const auto &[site_index, range_index] = inline_rows[row];
        const auto &site = pdb_ptr->pdb_inline_sites[site_index];
        const auto *range = range_index ? &site.ranges[*range_index] : nullptr;
        switch (column) {
        case 0: return range && range->address ? location_text(Location{*range->address}) :
            range ? wxString::Format("section %u+0x%llX", site.section,
                static_cast<unsigned long long>(range->section_offset)) : wxString("unavailable");
        case 1: return range ? wxString::Format("%u", range->size) : wxString{};
        case 2: return range && range->line ? text(range->source_path) + wxString::Format(":%u", range->line) : wxString("unavailable");
        case 3: return wxString::Format("0x%X", site.inlinee_id);
        case 4: return wxString::Format("module %u, site 0x%X, depth %u", site.module_index, site.record_offset, site.depth) +
            (site.parent_record_offset ? wxString::Format(", parent 0x%X", *site.parent_record_offset) : wxString{}) + " / " + text(site.procedure_name);
        default: return text(site.status);
        }
    });
    pdb_inline_->activate = [this, pdb_ptr, inline_rows](std::size_t row) {
        if (row >= inline_rows.size()) return;
        const auto &[site, range] = inline_rows[row];
        if (range && pdb_ptr->pdb_inline_sites[site].ranges[*range].address && navigate)
            navigate(*pdb_ptr->pdb_inline_sites[site].ranges[*range].address);
    };
    pdb_inline_->fit_columns({0, 1, 2, 3, 4, 5});
    directories_->fit_columns({0, 1, 2, 3});
    resources_->fit_columns({0, 1, 2, 3, 4, 5, 6, 7, 8});
    bound_imports_->fit_columns({0, 1, 2, 3});
    exceptions_->fit_columns({0, 1, 2, 3});
    pdb_symbols_->fit_columns({0, 1, 2, 3, 4}); pdb_types_->fit_columns({0, 1, 2, 3}); pdb_lines_->fit_columns({0, 1, 2, 3});
}
} // namespace hexlab::desktop
