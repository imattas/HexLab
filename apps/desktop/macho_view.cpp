#include "macho_view.hpp"
#include <algorithm>
namespace hexlab::desktop {
namespace {
wxString number(std::uint64_t v) { return wxString::Format("0x%llx", static_cast<unsigned long long>(v)); }
wxString dec(std::uint64_t v) { return wxString::Format("%llu", static_cast<unsigned long long>(v)); }
wxString state(bool complete) { return complete ? "complete" : "partial"; }
wxString field(const char *name, std::uint64_t v) { return wxString(name) + "=" + number(v) + " "; }
wxString rtti_target_state(MachOEhFrameRttiTargetState value) {
    switch (value) {
    case MachOEhFrameRttiTargetState::unresolved: return "unresolved";
    case MachOEhFrameRttiTargetState::null_catch_all: return "null catch-all";
    case MachOEhFrameRttiTargetState::readable_pointer: return "readable pointer";
    case MachOEhFrameRttiTargetState::exact_defined_rtti_symbol: return "exact RTTI symbol";
    case MachOEhFrameRttiTargetState::ambiguous_defined_rtti_symbols: return "ambiguous RTTI symbols";
    case MachOEhFrameRttiTargetState::invalid_pointer: return "invalid pointer";
    }
    return "unknown";
}
} // namespace
wxString macho_symbol_state(MachOSymbolState value) {
    switch (value) {
    case MachOSymbolState::undefined:
        return "undefined";
    case MachOSymbolState::defined:
        return "defined";
    case MachOSymbolState::absolute:
        return "absolute";
    case MachOSymbolState::common:
        return "common";
    case MachOSymbolState::indirect:
        return "indirect";
    case MachOSymbolState::prebound_undefined:
        return "prebound undefined";
    case MachOSymbolState::debug:
        return "debug";
    case MachOSymbolState::unknown:
        return "unknown";
    }
    return "unknown";
}
wxString macho_metadata_cell(const DocumentSnapshot &doc, const MachOMetadataRow &row, int column) {
    static const char *const labels[] = {"Header",
                                         "Slice",
                                         "Command",
                                         "Segment",
                                         "Section",
                                         "Symbol table",
                                         "Symbol",
                                         "Library",
                                         "Path",
                                         "Entry",
                                         "Function start",
                                         "Dynamic symbols",
                                         "Relocation table",
                                         "Relocation",
                                         "Dyld stream",
                                         "Dyld operation",
                                         "Dyld fixup",
                                         "Dyld export",
                                         "Chained header",
                                         "Chained import",
                                         "Chained starts",
                                         "Chained pointer",
                                         "Data-in-code table",
                                         "Data-in-code",
                                         "Encryption",
                                         "Signature",
                                         "EH frame function",
                                         "EH frame personality",
                                         "LSDA call site",
                                         "LSDA action",
                                         "LSDA type info"};
    static_assert(std::size(labels) == static_cast<std::size_t>(MachOMetadataKind::count));
    if (column == 0)
        return wxString(labels[static_cast<std::size_t>(row.kind)]) + " #" + dec(row.index);
    if (column == 1)
        return location_text(row.source);
    const auto &m = *doc.metadata_view().macho;
    const auto n = static_cast<std::size_t>(row.index);
    const auto at = [&](const std::optional<Address> &v) {
        return v ? location_text(*v, doc.image.get()) : wxString("unmapped");
    };
    switch (row.kind) {
    case MachOMetadataKind::header: {
        const auto &s = m.container.slices[m.selected_slice];
        const auto &h = s.header;
        return column == 2 ? wxString(h.is_64 ? "Mach-O64 " : "Mach-O32 ") +
                                 (h.order == ByteOrder::little ? "little endian" : "big endian")
                           : field("cpu", h.cpu_type) + field("subtype", h.cpu_subtype) + field("type", h.file_type) +
                                 field("flags", h.flags) + "selected=" + dec(m.selected_slice) + " " +
                                 state(doc.metadata_complete);
    }
    case MachOMetadataKind::slice: {
        const auto &s = m.container.slices[n];
        return column == 2 ? field("cpu", s.cpu_type) + field("subtype", s.cpu_subtype)
                           : field("size", s.size) + field("alignment", s.alignment) + field("reserved", s.reserved) +
                                 (n == m.selected_slice ? "selected" : "not selected");
    }
    case MachOMetadataKind::command: {
        const auto &r = m.container.slices[m.selected_slice].header.commands[n];
        return column == 2 ? field("type", r.command) : field("size", r.size);
    }
    case MachOMetadataKind::segment: {
        const auto &r = m.segments[n];
        return column == 2
                   ? preview_text(r.name)
                   : field("vm", r.address) + field("memory", r.memory_size) + field("file", r.file_offset.value) +
                         field("initialized", r.file_size) + field("protection", r.initial_protection) +
                         field("maximum", r.maximum_protection) + field("flags", r.flags);
    }
    case MachOMetadataKind::section: {
        const auto &r = m.sections[n];
        return column == 2 ? preview_text(r.segment_name) + "/" + preview_text(r.name)
                           : field("vm", r.address) + field("size", r.size) + field("flags", r.flags) +
                                 field("relocations", r.relocation_count) +
                                 (r.file_offset ? field("backing", r.file_offset->value) : wxString("uninitialized"));
    }
    case MachOMetadataKind::symbol_table: {
        const auto &r = m.symbol_tables[n];
        return column == 2 ? "count=" + dec(r.count)
                           : field("stride", r.stride) + field("strings", r.string_offset.value) +
                                 field("string-size", r.string_size);
    }
    case MachOMetadataKind::symbol: {
        const auto &r = m.symbols[n];
        return column == 2 ? preview_text(r.name)
                           : macho_symbol_state(r.state) + " " + at(r.address) + " " + field("raw-value", r.value) +
                                 field("type", r.type) + field("descriptor", r.descriptor);
    }
    case MachOMetadataKind::library: {
        const auto &r = m.libraries[n];
        return column == 2 ? preview_text(r.name)
                           : field("command", r.command) +
                                 (r.ordinal ? "ordinal=" + dec(*r.ordinal) + " " : wxString("identity ")) +
                                 field("current", r.current_version) + field("compatible", r.compatibility_version);
    }
    case MachOMetadataKind::path: {
        const auto &r = m.paths[n];
        return column == 2 ? preview_text(r.name) : field("command", r.command);
    }
    case MachOMetadataKind::entry: {
        const auto &r = m.entries[n];
        return column == 2 ? at(r.address)
                           : field("command", r.command) + field("flavor", r.flavor) + field("stack", r.stack_size);
    }
    case MachOMetadataKind::function_start: {
        const auto &r = m.function_starts[n];
        return column == 2 ? at(r.address) : field("delta", r.delta);
    }
    case MachOMetadataKind::dynamic_symbols: {
        const auto &r = m.dynamic_symbol_tables[n];
        wxString value;
        if (column == 2)
            for (const auto &range : r.ranges)
                value += "[" + dec(range.begin) + "," + dec(range.count) + "] ";
        else
            for (const auto &table : r.tables)
                value += field("file", table.offset.value) + "count=" + dec(table.count) + " ";
        return value;
    }
    case MachOMetadataKind::relocation_table: {
        const auto &r = m.relocation_tables[n];
        return column == 2 ? "count=" + dec(r.count)
                           : field("owner", r.owner) + field("kind", static_cast<unsigned>(r.kind));
    }
    case MachOMetadataKind::relocation: {
        const auto &r = m.relocations[n];
        return column == 2 ? field("type", r.type) + field("symbol", r.symbol_number)
                           : at(r.place) + " " + field("raw-address", r.raw_address) + field("raw-info", r.raw_info) +
                                 field("width", r.field_size) + (r.pc_relative ? "PC relative " : "") +
                                 (r.retained ? "retained" : "not retained");
    }
    case MachOMetadataKind::dyld_stream: {
        const auto &r = m.dyld_streams[n];
        return column == 2 ? field("kind", static_cast<unsigned>(r.kind)) : field("size", r.size) + state(r.complete);
    }
    case MachOMetadataKind::dyld_operation: {
        const auto &r = m.dyld_operations[n];
        return column == 2 ? field("opcode", r.byte)
                           : field("stream", r.stream) + field("size", r.encoded_size) +
                                 (r.symbol ? preview_text(*r.symbol) : wxString{});
    }
    case MachOMetadataKind::dyld_fixup: {
        const auto &r = m.dyld_fixups[n];
        return column == 2
                   ? preview_text(r.symbol) + " " + at(r.place)
                   : field("stream", r.stream) + field("type", r.type) + field("width", r.field_size) +
                         wxString::Format("addend=%lld ", static_cast<long long>(r.addend)) +
                         (r.library_ordinal ? wxString::Format("ordinal=%d ", *r.library_ordinal) : wxString{}) +
                         "declared fixup";
    }
    case MachOMetadataKind::dyld_export: {
        const auto &r = m.dyld_exports[n];
        return column == 2 ? preview_text(r.name) + " " + at(r.address)
                           : field("flags", r.flags) + state(r.complete) +
                                 (r.import_name ? " import=" + preview_text(*r.import_name) : wxString{}) +
                                 (r.resolver_address ? " resolver=" + at(r.resolver_address) : wxString{});
    }
    case MachOMetadataKind::chain_header: {
        const auto &r = m.chained_headers[n];
        return column == 2 ? "imports=" + dec(r.imports_count)
                           : field("version", r.version) + field("format", r.imports_format) +
                                 field("starts", r.starts_offset) + field("imports", r.imports_offset) +
                                 field("symbols", r.symbols_offset) + state(r.complete);
    }
    case MachOMetadataKind::chain_import: {
        const auto &r = m.chained_imports[n];
        return column == 2
                   ? (r.name ? preview_text(*r.name) : wxString("unavailable"))
                   : wxString::Format("ordinal=%d addend=%lld ", r.library_ordinal, static_cast<long long>(r.addend)) +
                         field("raw", r.raw_info) + state(r.complete);
    }
    case MachOMetadataKind::chain_start: {
        const auto &r = m.chained_starts[n];
        return column == 2 ? field("format", r.pointer_format)
                           : field("segment", r.segment_index) + field("offset", r.segment_offset) +
                                 field("page-size", r.page_size) + "page-records=" + dec(r.page_starts.size()) + " " +
                                 state(r.complete);
    }
    case MachOMetadataKind::chain_pointer: {
        const auto &r = m.chained_pointers[n];
        const auto format = m.chained_starts[r.starts].pointer_format;
        return column == 2 ? at(r.place) + " " + field("raw", r.raw)
                           : field("next", r.next) + field("format", format) +
                                 ((format == 8 || format == 11)
                                      ? field("cache-level", (r.raw >> 30) & 3) +
                                            field("target-offset", r.target.value_or(0)) + "base unresolved "
                                      : wxString()) +
                                 (r.bind ? "bind " : "rebase ") + (r.authenticated ? "authenticated " : "") +
                                 (r.non_pointer ? "non-pointer " : "") + state(r.complete);
    }
    case MachOMetadataKind::data_in_code_table: {
        const auto &r = m.data_in_code_tables[n];
        return column == 2 ? field("size", r.size) : wxString("declared data-in-code");
    }
    case MachOMetadataKind::data_in_code: {
        const auto &r = m.data_in_code[n];
        return column == 2 ? field("offset", r.raw_offset) + field("length", r.length)
                           : field("kind", r.kind) + (r.offset ? field("backing", r.offset->value)
                                                               : wxString("ambiguous or uninitialized backing"));
    }
    case MachOMetadataKind::encryption: {
        const auto &r = m.encryption[n];
        return column == 2 ? field("cryptid", r.cryptid)
                           : field("file", r.offset.value) + field("size", r.size) +
                                 (r.cryptid ? "encrypted; decoding excluded" : "clear");
    }
    case MachOMetadataKind::signature: {
        const auto &r = m.code_signatures[n];
        return column == 2 ? field("size", r.size) : wxString("declared bytes; authentication unavailable");
    }
    case MachOMetadataKind::eh_frame_function: {
        const auto &r = m.eh_frame_functions[n];
        if (column == 2)
            return at(r.address) + (r.personality_symbol ? " " + preview_text(*r.personality_symbol)
               : (r.personality ? " personality=" + at(r.personality)
                  : (r.has_personality_field ? wxString(" personality field present, pointer unresolved")
                                             : wxString(" no personality field"))));
        return field("fde-record", r.record_file_offset) + field("function-size", r.size) +
               field("section", r.section) + field("return-reg", r.return_register) +
               (r.lsda ? "lsda=" + at(r.lsda) + " " : wxString("no LSDA ")) +
               (r.personality_kind == MachOPersonalityKind::itanium_cxx ? "Itanium C++ " :
                (r.has_personality_field ? "unclassified personality " : "no personality field ")) +
               state(r.lsda_complete);
    }
    case MachOMetadataKind::eh_frame_personality: {
        const auto &r = m.eh_frame_functions[row.owner_index];
        if (column == 2)
            return r.personality_symbol ? preview_text(*r.personality_symbol)
                 : (r.personality ? at(r.personality)
                    : (r.has_personality_field ? wxString("present, pointer unresolved") : wxString("absent")));
        return wxString(r.has_personality_field ? "present " : "absent ") +
               (r.personality_kind == MachOPersonalityKind::itanium_cxx ? wxString("recognized Itanium C++ personality ")
                  : wxString(r.has_personality_field ? "unclassified personality " : "no personality field ")) +
               (r.has_personality_field ? field("encoding", r.personality_encoding) : wxString()) +
               (r.personality_source ? field("CIE-source", r.personality_source->value)
                                     : field("FDE-source", r.record_file_offset)) +
               field("encoded-size", r.personality_source_size);
    }
    case MachOMetadataKind::eh_frame_call_site: {
        const auto &fde = m.eh_frame_functions[row.owner_index];
        const auto &r = fde.call_sites[row.item_index];
        if (column == 2)
            return at(fde.address) + " + " + number(r.start) + " -> " +
                   (r.landing_pad ? "LP+" + number(r.landing_pad) : wxString("no landing pad"));
        wxString value = field("length", r.length) + field("action", r.action) +
               field("action-chain-records", r.action_chain.size()) + field("encoded-at", r.record_offset) +
               field("encoded-size", r.encoded_size) +
               (fde.lsda_complete ? "LSDA complete" : "LSDA partial");
        constexpr std::size_t displayed_action_chain = 8;
        for (std::size_t i = 0; i < std::min(r.action_chain.size(), displayed_action_chain); ++i)
            value += " action[" + dec(i) + "]=" + number(r.action_chain[i]);
        if (r.action_chain.size() > displayed_action_chain)
            value += " remaining-actions=" + dec(r.action_chain.size() - displayed_action_chain);
        return value;
    }
    case MachOMetadataKind::eh_frame_action: {
        const auto &fde = m.eh_frame_functions[row.owner_index];
        const auto &r = fde.actions[row.item_index];
        if (column == 2)
            return at(fde.address) + " action@" + number(r.record_offset);
        wxString value = wxString::Format("filter=%lld displacement=%lld ",
            static_cast<long long>(r.type_filter), static_cast<long long>(r.next_displacement));
        if (r.next_record_offset) value += "next=" + number(*r.next_record_offset) + " ";
        if (r.type_info_index) value += field("type-index", *r.type_info_index);
        return value + field("encoded-size", r.encoded_size);
    }
    case MachOMetadataKind::eh_frame_type_info: {
        const auto &fde = m.eh_frame_functions[row.owner_index];
        const auto &r = fde.type_infos[row.item_index];
        if (column == 2) {
            wxString value = r.address ? at(r.address) : number(r.value);
            for (const auto &symbol : r.rtti_symbols) value += " " + preview_text(symbol);
            return value;
        }
        return field("index", r.index) + field("record", r.record_offset) + field("encoding", r.encoding) +
               field("encoded-size", r.encoded_size) + rtti_target_state(r.target_state) +
                (r.null_pointer ? wxString(" null") : wxString{});
    }
    case MachOMetadataKind::count:
        return {};
    }
    return {};
}
} // namespace hexlab::desktop
