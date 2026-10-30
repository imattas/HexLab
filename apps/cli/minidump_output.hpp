#pragma once
#include "hexlab/image/metadata.hpp"
#include <algorithm>
#include <iomanip>
#include <iterator>
#include <ostream>
#include <string>
#include <string_view>

namespace hexlab::cli {
inline std::string quote_minidump_text(std::string_view value) {
    constexpr char hex[] = "0123456789abcdef";
    std::string out = "\"";
    for (const auto raw : value) {
        const auto byte = static_cast<unsigned char>(raw);
        if (raw == '"' || raw == '\\') { out.push_back('\\'); out.push_back(raw); }
        else if (byte < 0x20 || byte == 0x7f) {
            out += "\\x"; out.push_back(hex[byte >> 4]); out.push_back(hex[byte & 0xf]);
        } else out.push_back(raw);
    }
    out.push_back('"');
    return out;
}
inline const char *minidump_architecture_name(std::uint16_t architecture) {
    switch (architecture) {
    case 0: return "x86";
    case 9: return "AMD64";
    case 12: return "ARM64";
    case 0x8003: return "Breakpad ARM64";
    case 5: return "ARM";
    default: return "unknown";
    }
}
inline void minidump_version_tuple(std::ostream &out, std::uint32_t high, std::uint32_t low) {
    out << ((high >> 16) & 0xffff) << '.' << (high & 0xffff) << '.'
        << ((low >> 16) & 0xffff) << '.' << (low & 0xffff);
}
inline void minidump_context(std::ostream &out, const MinidumpContext &context, const char *indent) {
    out << indent << "Context architecture=" << minidump_architecture_name(context.processor_architecture)
        << " flags=0x" << std::hex << context.flags << std::dec
        << " control=" << (context.control_valid ? "valid" : "unavailable")
        << " integer=" << (context.integer_valid ? "valid" : "unavailable") << '\n';
    for (const auto &reg : context.registers) {
        out << indent << "  " << reg.name << "=0x" << std::hex;
        if (reg.width > 64) {
            constexpr char digits[] = "0123456789abcdef";
            for (auto it = reg.bytes.rbegin(); it != reg.bytes.rend(); ++it) {
                const auto byte = std::to_integer<unsigned>(*it);
                out << digits[byte >> 4] << digits[byte & 15];
            }
        } else out << reg.value;
        out << std::dec << '\n';
    }
    for (const auto &diagnostic : context.diagnostics)
        out << indent << "  Context note: " << diagnostic << '\n';
}
inline void minidump_quoted_text(std::ostream &out, const std::string &value) {
    constexpr std::size_t limit = 256;
    out << '"';
    for (std::size_t i = 0; i < std::min(value.size(), limit); ++i) {
        const auto byte = static_cast<unsigned char>(value[i]);
        if (byte == '"' || byte == '\\') out << '\\' << static_cast<char>(byte);
        else if (byte < 0x20 || byte == 0x7f) out << "\\x" << std::hex << std::setw(2) << std::setfill('0')
                                                   << static_cast<unsigned>(byte) << std::dec << std::setfill(' ');
        else out << static_cast<char>(byte);
    }
    if (value.size() > limit) out << "...";
    out << '"';
}
inline void minidump_description(std::ostream &out, const ImageMetadata &metadata) {
    if (!metadata.minidump) return;
    const auto &dump = *metadata.minidump;
    out << "Minidump: architecture=" << minidump_architecture_name(dump.processor_architecture)
        << " threads=" << dump.threads.size() << " modules=" << dump.modules.size()
        << " memory-regions=" << dump.memory.size()
        << " memory-info-rows=" << dump.memory_info.size() << '\n';
    constexpr std::size_t memory_info_limit = 128;
    for (std::size_t i = 0; i < std::min(dump.memory_info.size(), memory_info_limit); ++i) {
        const auto &row = dump.memory_info[i];
        out << "  MemoryInfo[" << i << "] base=0x" << std::hex << row.base
            << " size=0x" << row.region_size << " allocation-base=0x" << row.allocation_base
            << " allocation-protect=0x" << row.allocation_protect << " protect=0x" << row.protect
            << " state=0x" << row.state << " type=0x" << row.type
            << " record-file=0x" << row.record_file_offset.value << std::dec << '\n';
    }
    if (dump.memory_info.size() > memory_info_limit)
        out << "  MemoryInfo rows omitted=" << (dump.memory_info.size() - memory_info_limit) << '\n';
    if (dump.system_info) {
        const auto &system = *dump.system_info;
        out << "  Windows system version=" << system.major_version << '.' << system.minor_version
            << " build=" << system.build_number << " platform=" << system.platform_id
            << " processors=" << static_cast<unsigned>(system.processor_count)
            << " processor-level=" << system.processor_level << " revision=" << system.processor_revision
            << " product-type=" << static_cast<unsigned>(system.product_type)
            << " suite-mask=0x" << std::hex << system.suite_mask << std::dec;
        if (!system.service_pack.empty()) {
            out << " service-pack=";
            minidump_quoted_text(out, system.service_pack);
        }
        out << " cpu-info-file=0x" << std::hex << system.cpu_information_file_offset.value << " bytes=";
        for (const auto byte : system.cpu_information)
            out << std::setw(2) << std::setfill('0') << std::to_integer<unsigned>(byte);
        out << std::dec << std::setfill(' ') << '\n';
        if (system.x86_cpu_info) {
            const auto &cpu = *system.x86_cpu_info;
            out << "  x86 CPU vendor=";
            out << quote_minidump_text(std::string_view(cpu.vendor_id.data(), cpu.vendor_id.size()));
            out << " version=0x" << std::hex << cpu.version_information
                << " feature-info=0x" << cpu.feature_information
                << " amd-extended-features=0x" << cpu.amd_extended_cpu_features
                << " source=0x" << cpu.source_file_offset.value << std::dec << '\n';
        }
    }
    if (dump.process_info) {
        const auto &process = *dump.process_info;
        out << "  Process metadata flags=0x" << std::hex << process.flags << std::dec;
        if (process.process_id) out << " id=" << *process.process_id;
        if (process.process_create_time) out << " create-time=" << *process.process_create_time;
        if (process.process_user_time) out << " user-time=" << *process.process_user_time;
        if (process.process_kernel_time) out << " kernel-time=" << *process.process_kernel_time;
        out << " stream-file=0x" << std::hex << process.stream_file_offset.value << std::dec
            << " declared-bytes=" << process.declared_size << '\n';
        static constexpr const char *power_names[] = {
            "processor-max-mhz", "processor-current-mhz", "processor-mhz-limit",
            "processor-max-idle-state", "processor-current-idle-state"};
        const std::array<std::optional<std::uint32_t>, 5> power_values = {
            process.processor_max_mhz, process.processor_current_mhz, process.processor_mhz_limit,
            process.processor_max_idle_state, process.processor_current_idle_state};
        for (std::size_t index = 0; index < power_values.size(); ++index) {
            if (!power_values[index]) continue;
            out << "    " << power_names[index] << '=' << *power_values[index]
                << " field-file=0x" << std::hex << process.processor_power_field_offsets[index].value
                << std::dec;
            if (index < 3) out << " MHz";
            out << '\n';
        }
    }
    if (dump.vm_counters) {
        static constexpr const char *counter_names[] = {
            "peak-working-set", "working-set", "quota-peak-paged-pool", "paged-pool",
            "quota-peak-nonpaged-pool", "nonpaged-pool", "pagefile", "peak-pagefile",
            "private-usage", "peak-virtual", "virtual", "private-working-set", "shared-commit",
            "job-shared-commit", "job-private-commit", "job-peak-private-commit",
            "job-private-commit-limit", "job-total-commit-limit"};
        const auto &vm = *dump.vm_counters;
        out << "  Process VM counters revision=" << vm.revision << " flags=0x" << std::hex << vm.flags
            << std::dec << " page-faults=" << vm.page_fault_count << " stream-file=0x"
            << std::hex << vm.stream_file_offset.value << std::dec << " stream-bytes=" << vm.stream_size << '\n';
        for (std::size_t index = 0; index < vm.counter_count && index < std::size(counter_names); ++index)
            out << "    " << counter_names[index] << "=" << vm.counters[index] << " bytes\n";
    }
    if (dump.function_tables) {
        const auto &tables = *dump.function_tables;
        constexpr std::size_t max_function_tables = 128;
        const auto count = std::min(tables.tables.size(), max_function_tables);
        out << "  Function tables count=" << tables.tables.size() << " stream-file=0x" << std::hex
            << tables.stream_file_offset.value << std::dec << " stream-bytes=" << tables.stream_size
            << " entry-bytes=" << tables.function_entry_size << " native-descriptor-bytes="
            << tables.native_descriptor_size << '\n';
        for (std::size_t index = 0; index < count; ++index) {
            const auto &table = tables.tables[index];
            out << "    Function table " << index << " range=0x" << std::hex << table.minimum_address
                << "-0x" << table.maximum_address << " base=0x" << table.base_address << std::dec
                << " entries=" << table.entry_count << " descriptor-file=0x" << std::hex
                << table.descriptor_file_offset.value << " native-file=0x" << table.native_descriptor_file_offset.value
                << " entries-file=0x" << table.entries_file_offset.value << std::dec << '\n';
        }
        if (tables.tables.size() > count)
            out << "  (" << tables.tables.size() - count << " additional function tables omitted from CLI summary)\n";
    }
    if (dump.system_memory_info) {
        const auto &memory = *dump.system_memory_info;
        out << "  System memory info revision=" << memory.revision << " flags=0x" << std::hex << memory.flags
            << std::dec << " page-size=" << memory.page_size << " physical-pages=" << memory.physical_page_count
            << " processors=" << memory.processor_count << " user-range=0x" << std::hex
            << memory.minimum_user_address << "-0x" << memory.maximum_user_address << std::dec
            << " stream-file=0x" << std::hex << memory.stream_file_offset.value << std::dec
            << " stream-bytes=" << memory.stream_size << '\n';
        if (memory.file_cache) {
            const auto &cache = *memory.file_cache;
            out << "    File cache current=" << cache.current_size << " peak=" << cache.peak_size
                << " page-faults=" << cache.page_fault_count << " working-set=" << cache.minimum_working_set
                << "-" << cache.maximum_working_set << " transition-pages="
                << cache.current_size_including_transition_pages << "/"
                << cache.peak_size_including_transition_pages;
            if (cache.transition_repurpose_count_valid)
                out << " transition-repurpose-count=" << cache.transition_repurpose_count;
            out << " flags=0x" << std::hex << cache.flags << std::dec << '\n';
        }
        if (memory.basic_performance) {
            const auto &performance = *memory.basic_performance;
            out << "    Basic performance available-pages=" << performance.available_pages
                << " committed-pages=" << performance.committed_pages << " commit-limit="
                << performance.commit_limit << " peak-commitment=" << performance.peak_commitment << '\n';
        }
    }
    constexpr std::size_t max_comments = 2;
    constexpr std::size_t max_comment_preview_bytes = 64;
    for (std::size_t index = 0; index < std::min(dump.comments.size(), max_comments); ++index) {
        const auto &comment = dump.comments[index];
        out << "  Comment stream=" << comment.stream_type
            << (comment.stream_type == 10 ? " kind=ANSI" : " kind=Unicode")
            << " bytes=" << comment.stream_size << " source=0x" << std::hex
            << comment.stream_file_offset.value << std::dec
            << " captured=" << comment.captured_bytes.size() << " preview-hex=";
        const auto preview = std::min(comment.captured_bytes.size(), max_comment_preview_bytes);
        for (std::size_t byte = 0; byte < preview; ++byte)
            out << std::hex << std::setw(2) << std::setfill('0')
                << std::to_integer<unsigned>(comment.captured_bytes[byte]);
        out << std::dec << std::setfill(' ');
        if (comment.captured_bytes.size() > preview || comment.truncated)
            out << "...";
        if (comment.stream_type == 11) {
            if (comment.decoded_text) out << " decoded-text=" << quote_minidump_text(*comment.decoded_text);
            else out << " decoded-text=unavailable";
            if (comment.truncated) out << " decoded-text-truncated=true";
        }
        out << '\n';
    }
    if (dump.linux_proc_status) {
        const auto &status = *dump.linux_proc_status;
        out << "  Linux proc-status bytes=" << status.declared_size
            << " captured=" << status.captured_text.size()
            << " complete=" << (status.complete ? "true" : "false")
            << " source=0x" << std::hex << status.stream_file_offset.value << std::dec << '\n';
        constexpr std::size_t max_status_fields = 64;
        for (std::size_t index = 0; index < std::min(status.fields.size(), max_status_fields); ++index) {
            const auto &field = status.fields[index];
            out << "    "; minidump_quoted_text(out, field.key);
            out << '='; minidump_quoted_text(out, field.value);
            out << " source=0x" << std::hex << field.line_file_offset.value << std::dec << '\n';
        }
        if (status.fields.size() > max_status_fields)
            out << "    Linux proc-status fields omitted=" << (status.fields.size() - max_status_fields) << '\n';
    }
    constexpr std::size_t max_linux_text_streams = 8, max_linux_text_preview = 96;
    for (std::size_t index = 0; index < std::min(dump.linux_text_streams.size(), max_linux_text_streams); ++index) {
        const auto &text = dump.linux_text_streams[index];
        const char *name = text.stream_type == 0x47670003 ? "cpuinfo" :
            text.stream_type == 0x47670005 ? "lsb-release" :
            text.stream_type == 0x47670006 ? "cmdline" :
            text.stream_type == 0x47670007 ? "environ" :
            text.stream_type == 0x47670008 ? "auxv" : "maps";
        out << "  Breakpad Linux " << name << " bytes=" << text.declared_size
            << " captured=" << text.captured_bytes.size() << " source=0x"
            << std::hex << text.stream_file_offset.value << std::dec;
        if (text.truncated) out << " truncated=true";
        const auto preview_size = std::min(text.captured_bytes.size(), max_linux_text_preview);
        if (preview_size) {
            const auto *data = reinterpret_cast<const char *>(text.captured_bytes.data());
            out << " preview=";
            minidump_quoted_text(out, std::string(data, preview_size));
            if (preview_size < text.captured_bytes.size() || text.truncated) out << "...";
        }
        out << '\n';
        if (text.stream_type == 0x47670009) {
            constexpr std::size_t max_linux_maps = 64;
            out << "    Linux maps: " << text.memory_maps.size()
                << " complete=" << (text.maps_complete ? "true" : "false") << '\n';
            for (std::size_t map_index = 0; map_index < std::min(text.memory_maps.size(), max_linux_maps); ++map_index) {
                const auto &map = text.memory_maps[map_index];
                out << "      Map: 0x" << std::hex << map.start << "-0x" << map.end << std::dec
                    << " permissions=" << map.permissions << " file-offset=0x" << std::hex << map.file_offset
                    << " device=" << map.device_major << ':' << map.device_minor << std::dec
                    << " inode=" << map.inode << " source=0x" << std::hex << map.line_file_offset.value << std::dec;
                if (!map.path.empty()) { out << " path="; minidump_quoted_text(out, map.path); }
                out << '\n';
            }
            if (text.memory_maps.size() > max_linux_maps)
                out << "      Maps omitted: " << text.memory_maps.size() - max_linux_maps << '\n';
        }
        if (text.stream_type == 0x47670008) {
            constexpr std::size_t max_auxv_entries = 64;
            out << "    Linux auxv entries: " << text.auxiliary_values.size()
                << " complete=" << (text.auxiliary_values_complete ? "true" : "false") << '\n';
            for (std::size_t value_index = 0;
                 value_index < std::min(text.auxiliary_values.size(), max_auxv_entries); ++value_index) {
                const auto &value = text.auxiliary_values[value_index];
                out << "      type=0x" << std::hex << value.type << " value=0x" << value.value
                    << " word-bytes=" << std::dec << static_cast<unsigned>(value.word_size)
                    << " source=0x" << std::hex << value.record_file_offset.value << std::dec << '\n';
            }
            if (text.auxiliary_values.size() > max_auxv_entries)
                out << "      Auxv entries omitted: " << text.auxiliary_values.size() - max_auxv_entries << '\n';
        }
    }
    if (dump.assertion) {
        const auto &assertion = *dump.assertion;
        const char *type_name = assertion.type == 0 ? "unknown" : assertion.type == 1 ? "invalid-parameter" :
                                assertion.type == 2 ? "pure-virtual-call" : "extension";
        out << "  Breakpad assertion type=" << assertion.type << '(' << type_name << ") line=" << assertion.line
            << " stream-file=0x" << std::hex << assertion.stream_file_offset.value << std::dec << " expression=";
        minidump_quoted_text(out, assertion.expression);
        out << " function="; minidump_quoted_text(out, assertion.function);
        out << " file="; minidump_quoted_text(out, assertion.file);
        out << '\n';
    }
    constexpr std::size_t max_threads = 256;
    const auto count = std::min(dump.threads.size(), max_threads);
    for (std::size_t i = 0; i < count; ++i) {
        const auto &thread = dump.threads[i];
        const auto name = std::lower_bound(dump.thread_names.begin(), dump.thread_names.end(), thread.id,
            [](const auto &row, std::uint32_t id) { return row.thread_id < id; });
        out << "  Thread " << thread.id << " stack=0x" << std::hex << thread.stack_address
            << "+0x" << thread.stack_size << std::dec << " context-bytes=" << thread.context_size;
        if (thread.extended_record)
            out << " backing-store=0x" << std::hex << thread.backing_store_address
                << "+0x" << thread.backing_store_size << std::dec;
        if (name != dump.thread_names.end() && name->thread_id == thread.id) {
            out << " name=";
            minidump_quoted_text(out, name->name);
        }
        out << '\n';
        if (thread.context) minidump_context(out, *thread.context, "    ");
    }
    if (dump.threads.size() > count)
        out << "  (" << dump.threads.size() - count << " additional threads omitted from CLI summary)\n";
    constexpr std::size_t max_thread_info = 256;
    const auto thread_info_count = std::min(dump.thread_info.size(), max_thread_info);
    for (std::size_t i = 0; i < thread_info_count; ++i) {
        const auto &thread = dump.thread_info[i];
        out << "  Thread info " << thread.thread_id << " flags=0x" << std::hex << thread.dump_flags
            << " error=0x" << thread.dump_error << " exit-status=0x" << thread.exit_status
            << " start=0x" << thread.start_address << " affinity=0x" << thread.affinity << std::dec
            << " create-100ns=" << thread.create_time << " exit-100ns=" << thread.exit_time
            << " kernel-100ns=" << thread.kernel_time << " user-100ns=" << thread.user_time
            << " record-file=0x" << std::hex << thread.record_file_offset.value << std::dec << '\n';
    }
    if (dump.thread_info.size() > thread_info_count)
        out << "  (" << dump.thread_info.size() - thread_info_count << " additional thread-info records omitted from CLI summary)\n";
    constexpr std::size_t max_handles = 256;
    const auto handle_count = std::min(dump.handles.size(), max_handles);
    for (std::size_t i = 0; i < handle_count; ++i) {
        const auto &handle = dump.handles[i];
        out << "  Handle 0x" << std::hex << handle.handle << " attributes=0x" << handle.attributes
            << " access=0x" << handle.granted_access << std::dec
            << " handles=" << handle.handle_count << " pointers=" << handle.pointer_count;
        if (!handle.type_name.empty()) {
            out << " type=";
            minidump_quoted_text(out, handle.type_name);
        }
        if (!handle.object_name.empty()) {
            out << " name=";
            minidump_quoted_text(out, handle.object_name);
        }
        out << " record-file=0x" << std::hex << handle.record_file_offset.value;
        if (handle.object_info_rva) out << " object-info-rva=0x" << handle.object_info_rva;
        out << std::dec << '\n';
    }
    if (dump.handles.size() > handle_count)
        out << "  (" << dump.handles.size() - handle_count << " additional handles omitted from CLI summary)\n";
    if (dump.handle_operations) {
        const auto &list = *dump.handle_operations;
        constexpr std::size_t max_operations = 128;
        const auto operation_count = std::min(list.operations.size(), max_operations);
        out << "  Handle operation list count=" << list.operations.size()
            << " entry-bytes=" << list.entry_size << " header-file=0x" << std::hex
            << list.header_file_offset.value << std::dec << '\n';
        for (std::size_t index = 0; index < operation_count; ++index) {
            const auto &operation = list.operations[index];
            const auto type = operation.operation_type;
            const char *name = type == 0 ? "unused" : type == 1 ? "open" : type == 2 ? "close" : type == 3 ? "bad-reference" : "unknown";
            out << "    Operation " << index << " handle=0x" << std::hex << operation.handle
                << std::dec << " pid=" << operation.process_id << " tid=" << operation.thread_id
                << " type=" << type << '(' << name << ") trace-index=" << operation.backtrace_index
                << " depth=" << operation.backtrace_depth << " spare=0x" << std::hex << operation.spare
                << " record-file=0x" << operation.record_file_offset.value
                << std::dec << " record-bytes=" << operation.record_size << '\n';
            for (std::size_t frame = 0; frame < operation.backtrace_depth; ++frame)
                out << "      Return address " << frame << "=0x" << std::hex << operation.return_addresses[frame]
                    << " source-file=0x" << operation.return_addresses_file_offset.value + frame * 8 << std::dec << '\n';
        }
        if (list.operations.size() > operation_count)
            out << "  (" << list.operations.size() - operation_count << " additional handle operations omitted from CLI summary)\n";
    }
    if (dump.token_info) {
        const auto &list = *dump.token_info;
        constexpr std::size_t max_tokens = 128;
        const auto token_count = std::min(list.tokens.size(), max_tokens);
        out << "  Token info list count=" << list.tokens.size() << " stream-bytes=" << list.stream_size
            << " element-header-bytes=" << list.element_header_size << " header-file=0x" << std::hex
            << list.header_file_offset.value << std::dec << " (payloads opaque)\n";
        for (std::size_t index = 0; index < token_count; ++index) {
            const auto &token = list.tokens[index];
            out << "    Token " << index << " id=" << token.token_id << " handle=0x" << std::hex
                << token.token_handle << " record-file=0x" << token.record_file_offset.value
                << " payload-file=0x" << token.payload_file_offset.value << std::dec
                << " record-bytes=" << token.token_size << " payload-bytes=" << token.payload_size << '\n';
        }
        if (list.tokens.size() > token_count)
            out << "  (" << list.tokens.size() - token_count << " additional tokens omitted from CLI summary)\n";
    }
    constexpr std::size_t max_modules = 256;
    const auto pdb_status_name = [](MinidumpPdbStatus status) {
        switch (status) {
        case MinidumpPdbStatus::unavailable: return "unavailable";
        case MinidumpPdbStatus::missing: return "missing";
        case MinidumpPdbStatus::malformed: return "malformed";
        case MinidumpPdbStatus::mismatch: return "identity-mismatch";
        case MinidumpPdbStatus::ambiguous: return "ambiguous";
        case MinidumpPdbStatus::matched: return "matched";
        case MinidumpPdbStatus::unsupported_identity: return "unsupported-identity";
        }
        return "unknown";
    };
    const auto module_count = std::min(dump.modules.size(), max_modules);
    for (std::size_t i = 0; i < module_count; ++i) {
        const auto &module = dump.modules[i];
        out << "  Module " << module.name << " base=0x" << std::hex << module.image_base
            << " size=0x" << module.image_size << std::dec;
        if (module.version_info_signature_valid) {
            out << " file-version=";
            minidump_version_tuple(out, module.version_info[2], module.version_info[3]);
            out << " product-version=";
            minidump_version_tuple(out, module.version_info[4], module.version_info[5]);
            out << " version-file=0x" << std::hex << module.version_info_file_offset.value << std::dec;
        } else {
            out << " version-info=unrecognized version-file=0x" << std::hex
                << module.version_info_file_offset.value << std::dec;
        }
        if (module.codeview_kind == "RSDS") {
            out << " pdb=RSDS guid=";
            constexpr char hex[] = "0123456789abcdef";
            for (const auto byte : module.pdb_guid) {
                const auto value = std::to_integer<unsigned>(byte);
                out << hex[value >> 4] << hex[value & 15];
            }
            out << " age=" << module.pdb_age;
        } else if (module.codeview_kind == "NB10") {
            out << " pdb=NB10 timestamp=0x" << std::hex << module.pdb_timestamp << std::dec
                << " age=" << module.pdb_age;
        }
        if (!module.pdb_path.empty()) {
            out << " path=";
            minidump_quoted_text(out, module.pdb_path);
        }
        if (module.codeview_kind == "RSDS") {
            out << " pdb-binding=" << pdb_status_name(module.pdb_status)
                << " symbols=" << module.pdb_symbol_count
                << (module.pdb_symbols_complete ? "(complete)" : "(bounded/incomplete)");
            if (!module.bound_pdb_path.empty()) {
                out << " bound-pdb=";
                minidump_quoted_text(out, module.bound_pdb_path);
            }
            if (!module.pdb_diagnostic.empty()) {
                out << " pdb-note=";
                minidump_quoted_text(out, module.pdb_diagnostic);
            }
        }
        out << '\n';
    }
    if (dump.modules.size() > module_count)
        out << "  (" << dump.modules.size() - module_count << " additional modules omitted from CLI summary)\n";
    if (dump.exception) {
        const auto name = std::lower_bound(dump.thread_names.begin(), dump.thread_names.end(), dump.exception->thread_id,
            [](const auto &row, std::uint32_t id) { return row.thread_id < id; });
        out << "  Exception thread=" << dump.exception->thread_id << " code=0x"
            << std::hex << dump.exception->code << " address=0x" << dump.exception->address << std::dec;
        if (name != dump.thread_names.end() && name->thread_id == dump.exception->thread_id) {
            out << " name=";
            minidump_quoted_text(out, name->name);
        }
        out << '\n';
        if (dump.exception->context) minidump_context(out, *dump.exception->context, "    ");
    }
}
} // namespace hexlab::cli
