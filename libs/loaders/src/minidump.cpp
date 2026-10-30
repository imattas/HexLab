#include "hexlab/loaders/minidump.hpp"
#include "minidump_context.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <string_view>
#include <unordered_set>

namespace hexlab {
namespace {
constexpr std::uint32_t stream_thread_list = 3, stream_module_list = 4,
    stream_memory_list = 5, stream_exception = 6, stream_system_info = 7,
    stream_memory64_list = 9, stream_function_table = 13, stream_unloaded_module_list = 14,
    stream_misc_info = 15, stream_memory_info = 16, stream_thread_info = 17,
    stream_thread_names = 24, stream_handle_data = 12, stream_thread_ex_list = 8,
    stream_handle_operations = 18, stream_token_info = 19, stream_system_memory_info = 21, stream_process_vm_counters = 22,
    stream_comment_a = 10, stream_comment_w = 11,
    stream_assertion_info = 0x47670002, stream_linux_cpu_info = 0x47670003,
    stream_linux_proc_status = 0x47670004, stream_linux_lsb_release = 0x47670005,
    stream_linux_cmd_line = 0x47670006, stream_linux_environ = 0x47670007,
    stream_linux_auxv = 0x47670008, stream_linux_maps = 0x47670009;
constexpr std::uint64_t max_streams = 4096, max_memory_regions = 131072,
    max_modules = 65536, max_threads = 65536, max_handles = 131072,
    max_metadata_bytes = 64u * 1024u * 1024u;
constexpr std::uint64_t max_decoded_contexts = 4096;
constexpr std::size_t max_comment_capture_bytes = 4096;
constexpr std::size_t max_handle_object_info_per_handle = 1024;
constexpr std::uint64_t max_handle_object_info_records = 65536;
constexpr std::size_t misc_info5_xstate_offset = 832;
constexpr std::size_t xstate_config_feature_size = 528;
constexpr std::uint32_t misc_info_process_id = 0x1, misc_info_process_times = 0x2,
    misc_info_processor_power = 0x4;
constexpr std::size_t max_xstate_context_bytes = 64u * 1024u;

bool extent(std::uint64_t offset, std::uint64_t size, std::uint64_t total) {
    return offset <= total && size <= total - offset;
}
std::uint64_t u(std::span<const std::byte> bytes, std::size_t at, std::size_t width) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i)
        value |= std::uint64_t(std::to_integer<unsigned char>(bytes[at + i])) << (i * 8);
    return value;
}
Result<ByteView> read(const ByteStorage &storage, std::uint64_t offset, std::size_t size) {
    if (!extent(offset, size, storage.size()))
        return Error{ErrorCode::malformed, "Minidump file extent is outside the input"};
    auto bytes = storage.read_at({offset}, size);
    if (!bytes) return bytes.error();
    if (bytes.value().bytes.size() != size)
        return Error{ErrorCode::io, "Minidump source returned a short read"};
    return bytes.value();
}
bool parse_linux_map_line(std::string_view line, std::uint64_t source_offset,
                          MinidumpLinuxMemoryMap &result) {
    auto token = [&]() -> std::string_view {
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
        const auto end = line.find_first_of(" \t");
        const auto value = line.substr(0, end);
        line = end == std::string_view::npos ? std::string_view{} : line.substr(end);
        return value;
    };
    const auto number = [](std::string_view text, int base, std::uint64_t &value) {
        if (text.empty()) return false;
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
        return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
    };
    const auto range = token();
    const auto dash = range.find('-');
    if (dash == std::string_view::npos || !number(range.substr(0, dash), 16, result.start) ||
        !number(range.substr(dash + 1), 16, result.end) || result.start >= result.end) return false;
    result.permissions = std::string(token());
    if (result.permissions.size() != 4 ||
        (result.permissions[0] != 'r' && result.permissions[0] != '-') ||
        (result.permissions[1] != 'w' && result.permissions[1] != '-') ||
        (result.permissions[2] != 'x' && result.permissions[2] != '-') ||
        (result.permissions[3] != 'p' && result.permissions[3] != 's')) return false;
    result.readable = result.permissions[0] == 'r';
    result.writable = result.permissions[1] == 'w';
    result.executable = result.permissions[2] == 'x';
    result.shared = result.permissions[3] == 's';
    if (!number(token(), 16, result.file_offset)) return false;
    const auto device = token();
    const auto colon = device.find(':');
    std::uint64_t major = 0, minor = 0;
    if (colon == std::string_view::npos || !number(device.substr(0, colon), 16, major) ||
        !number(device.substr(colon + 1), 16, minor) || major > UINT32_MAX || minor > UINT32_MAX ||
        !number(token(), 10, result.inode)) return false;
    result.device_major = static_cast<std::uint32_t>(major);
    result.device_minor = static_cast<std::uint32_t>(minor);
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (line.size() > 4096) return false;
    result.path.assign(line);
    result.line_file_offset = FileOffset{source_offset};
    return true;
}
Result<std::string> utf8(std::uint64_t rva, const ByteStorage &storage, std::uint64_t &budget) {
    auto length = read(storage, rva, 4);
    if (!length) return length.error();
    const auto count = static_cast<std::uint32_t>(u(length.value().bytes, 0, 4));
    if (count > 131072 || (count & 1) || !extent(std::uint64_t(rva) + 4, count, storage.size()))
        return Error{ErrorCode::malformed, "Minidump UTF-16 string has an invalid extent"};
    auto data = read(storage, std::uint64_t(rva) + 4, count);
    if (!data) return data.error();
    std::string out;
    std::uint64_t utf8_size = 0;
    for (std::size_t at = 0; at < count; at += 2) {
        std::uint32_t cp = static_cast<std::uint32_t>(u(data.value().bytes, at, 2));
        if (cp >= 0xd800 && cp <= 0xdbff) {
            if (at + 4 <= count) {
                const auto low = static_cast<std::uint32_t>(u(data.value().bytes, at + 2, 2));
                if (low >= 0xdc00 && low <= 0xdfff) {
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                    at += 2;
                } else cp = 0xfffd;
            } else cp = 0xfffd;
        } else if (cp >= 0xdc00 && cp <= 0xdfff) cp = 0xfffd;
        utf8_size += cp <= 0x7f ? 1 : cp <= 0x7ff ? 2 : cp <= 0xffff ? 3 : 4;
    }
    if (budget > max_metadata_bytes || utf8_size > max_metadata_bytes - budget)
        return Error{ErrorCode::resource_limit, "Minidump metadata exceeds its byte budget"};
    budget += utf8_size;
    out.reserve(static_cast<std::size_t>(utf8_size));
    auto append = [&](std::uint32_t cp) {
        if (cp <= 0x7f) out.push_back(static_cast<char>(cp));
        else if (cp <= 0x7ff) {
            out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        } else if (cp <= 0xffff) {
            out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        } else {
            out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        }
    };
    for (std::size_t at = 0; at < count; at += 2) {
        std::uint32_t cp = static_cast<std::uint32_t>(u(data.value().bytes, at, 2));
        if (cp >= 0xd800 && cp <= 0xdbff) {
            if (at + 4 <= count) {
                const auto low = static_cast<std::uint32_t>(u(data.value().bytes, at + 2, 2));
                if (low >= 0xdc00 && low <= 0xdfff) {
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                    at += 2;
                } else cp = 0xfffd;
            } else cp = 0xfffd;
        } else if (cp >= 0xdc00 && cp <= 0xdfff) cp = 0xfffd;
        append(cp);
    }
    return out;
}
Result<std::string> fixed_utf16(std::span<const std::byte> bytes, std::uint64_t &budget) {
    if (bytes.size() != 256) return Error{ErrorCode::malformed, "Minidump assertion string has an invalid extent"};
    std::size_t units = 0;
    while (units < 128 && u(bytes, units * 2, 2) != 0) ++units;
    const auto codepoint_at = [&](std::size_t &at) {
        auto cp = static_cast<std::uint32_t>(u(bytes, at * 2, 2));
        if (cp >= 0xd800 && cp <= 0xdbff && at + 1 < units) {
            const auto low = static_cast<std::uint32_t>(u(bytes, (at + 1) * 2, 2));
            if (low >= 0xdc00 && low <= 0xdfff) { ++at; return 0x10000u + ((cp - 0xd800u) << 10) + low - 0xdc00u; }
        }
        return cp >= 0xd800 && cp <= 0xdfff ? 0xfffdu : cp;
    };
    std::uint64_t output_size = 0;
    for (std::size_t at = 0; at < units; ++at) {
        const auto cp = codepoint_at(at);
        output_size += cp <= 0x7f ? 1 : cp <= 0x7ff ? 2 : cp <= 0xffff ? 3 : 4;
    }
    if (budget > max_metadata_bytes || output_size > max_metadata_bytes - budget)
        return Error{ErrorCode::resource_limit, "Minidump metadata exceeds its byte budget"};
    budget += output_size;
    std::string out;
    out.reserve(static_cast<std::size_t>(output_size));
    const auto append = [&](std::uint32_t cp) {
        if (cp <= 0x7f) out.push_back(static_cast<char>(cp));
        else if (cp <= 0x7ff) { out.push_back(static_cast<char>(0xc0 | (cp >> 6))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); }
        else if (cp <= 0xffff) { out.push_back(static_cast<char>(0xe0 | (cp >> 12))); out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); }
        else { out.push_back(static_cast<char>(0xf0 | (cp >> 18))); out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f))); out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); }
    };
    for (std::size_t at = 0; at < units; ++at) append(codepoint_at(at));
    return out;
}
std::optional<std::string> decode_utf16le_text(std::span<const std::byte> bytes) {
    if (bytes.size() & 1u) return {};
    std::string output;
    output.reserve(bytes.size());
    const auto append = [&](std::uint32_t cp) {
        if (cp <= 0x7f) output.push_back(static_cast<char>(cp));
        else if (cp <= 0x7ff) {
            output.push_back(static_cast<char>(0xc0 | (cp >> 6)));
            output.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        } else if (cp <= 0xffff) {
            output.push_back(static_cast<char>(0xe0 | (cp >> 12)));
            output.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        } else {
            output.push_back(static_cast<char>(0xf0 | (cp >> 18)));
            output.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        }
    };
    for (std::size_t offset = 0; offset < bytes.size(); offset += 2) {
        auto code_unit = static_cast<std::uint16_t>(u(bytes, offset, 2));
        std::uint32_t cp = code_unit;
        if (code_unit >= 0xd800 && code_unit <= 0xdbff) {
            if (offset + 4 > bytes.size()) return {};
            const auto low = static_cast<std::uint16_t>(u(bytes, offset + 2, 2));
            if (low < 0xdc00 || low > 0xdfff) return {};
            cp = 0x10000u + ((code_unit - 0xd800u) << 10) + (low - 0xdc00u);
            offset += 2;
        } else if (code_unit >= 0xdc00 && code_unit <= 0xdfff) return {};
        append(cp);
    }
    return output;
}
Result<bool> parse_codeview(MinidumpModule &module, const ByteStorage &storage, std::uint64_t &budget) {
    constexpr std::uint64_t rsds = 0x53445352, nb10 = 0x3031424e;
    constexpr std::size_t max_path_bytes = 4096;
    if (module.cv_record_size < 4) return false;
    auto signature = read(storage, module.cv_record_rva, 4);
    if (!signature) return signature.error();
    const auto kind = u(signature.value().bytes, 0, 4);
    if (kind != rsds && kind != nb10) return false;

    const std::size_t fixed_size = kind == rsds ? 24 : 16;
    if (module.cv_record_size <= fixed_size)
        return Error{ErrorCode::malformed, "Minidump CodeView identity is truncated"};
    const auto path_bytes = std::min<std::uint64_t>(
        std::uint64_t(module.cv_record_size) - fixed_size, max_path_bytes + 1);
    const auto record_size = fixed_size + static_cast<std::size_t>(path_bytes);
    if (budget > max_metadata_bytes - std::min<std::uint64_t>(max_metadata_bytes, record_size))
        return Error{ErrorCode::resource_limit, "Minidump metadata exceeds its byte budget"};
    budget += record_size;
    auto record = read(storage, module.cv_record_rva, record_size);
    if (!record) return record.error();

    const auto path_begin = record.value().bytes.begin() + static_cast<std::ptrdiff_t>(fixed_size);
    const auto path_end = path_begin + static_cast<std::ptrdiff_t>(path_bytes);
    const auto terminator = std::find(path_begin, path_end, std::byte{0});
    if (terminator == path_end) {
        if (path_bytes == max_path_bytes + 1)
            return Error{ErrorCode::resource_limit, "Minidump CodeView PDB path exceeds its limit"};
        return Error{ErrorCode::malformed, "Minidump CodeView PDB path is unterminated"};
    }
    module.codeview_kind = kind == rsds ? "RSDS" : "NB10";
    module.pdb_path.assign(reinterpret_cast<const char *>(record.value().bytes.data() + fixed_size),
                           static_cast<std::size_t>(terminator - path_begin));
    if (kind == rsds) {
        for (std::size_t i = 0; i < module.pdb_guid.size(); ++i)
            module.pdb_guid[i] = record.value().bytes[4 + i];
        module.pdb_age = static_cast<std::uint32_t>(u(record.value().bytes, 20, 4));
    } else {
        module.pdb_timestamp = static_cast<std::uint32_t>(u(record.value().bytes, 8, 4));
        module.pdb_age = static_cast<std::uint32_t>(u(record.value().bytes, 12, 4));
    }
    return true;
}
struct StreamRow { std::uint32_t type, size, rva; };
struct ContextArchitectureSelection { std::uint16_t architecture = 0xffff; bool ambiguous = false; };
ContextArchitectureSelection select_compatible_context_architecture(
    std::uint16_t system_architecture, std::uint32_t context_size, std::span<const std::byte> prefix) {
    constexpr std::uint16_t x86 = 0, amd64 = 9, arm64 = 12;
    constexpr std::uint32_t family_mask = 0x00ff0000u;
    const auto family_at = [&](std::size_t offset) -> std::uint32_t {
        if (offset > prefix.size() || prefix.size() - offset < 4) return 0;
        return static_cast<std::uint32_t>(u(prefix, offset, 4)) & family_mask;
    };
    if (system_architecture != amd64 && system_architecture != arm64)
        return {system_architecture, false};
    const bool x86_context = context_size == 716 && family_at(0) == 0x00010000u;
    const bool arm64_context = system_architecture == arm64 && family_at(0) == 0x00400000u;
    const bool amd64_signature = context_size >= 1232 && family_at(48) == 0x00100000u;
    if (arm64_context) return {arm64, false};
    if (system_architecture == arm64 && amd64_signature && context_size != 1232)
        return {system_architecture, true};
    const bool amd64_context = amd64_signature && context_size == 1232;
    const unsigned candidates = static_cast<unsigned>(x86_context) + static_cast<unsigned>(amd64_context);
    if (candidates > 1) return {system_architecture, true};
    if (x86_context) return {x86, false};
    if (amd64_context) return {amd64, false};
    return {system_architecture, false};
}
struct Region { std::uint64_t begin, size, file; };
struct Protection {
    std::uint64_t begin, end, allocation_base;
    std::uint32_t allocation_protect, protect, state, type;
};
}

Result<LoadedImage> load_minidump(std::shared_ptr<const ByteStorage> storage, std::stop_token stop) {
    try {
        if (!storage) return Error{ErrorCode::invalid_argument, "Minidump loading requires input storage"};
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump loading canceled"};
        // Minidump mapping and metadata are derived from scattered stream and
        // memory records. Track every source read so patch invalidation can
        // prove whether a later project revision requires reparsing.
        auto tracking = TrackingStorage::create(std::move(storage));
        if (!tracking) return tracking.error();
        storage = tracking.value();
        auto header = read(*storage, 0, 32);
        if (!header) return header.error();
        if (u(header.value().bytes, 0, 4) != 0x504d444d)
            return Error{ErrorCode::malformed, "Invalid Minidump signature"};
        const auto stream_count = u(header.value().bytes, 8, 4);
        const auto directory_rva = u(header.value().bytes, 12, 4);
        if (stream_count > max_streams || !extent(directory_rva, stream_count * 12, storage->size()))
            return Error{ErrorCode::resource_limit, "Minidump stream directory exceeds validated limits"};
        auto directory = read(*storage, directory_rva, static_cast<std::size_t>(stream_count * 12));
        if (!directory) return directory.error();
        MinidumpMetadata metadata;
        metadata.timestamp = static_cast<std::uint32_t>(u(header.value().bytes, 20, 4));
        metadata.flags = u(header.value().bytes, 24, 8);
        metadata.flags_low = static_cast<std::uint32_t>(metadata.flags);
        std::vector<StreamRow> streams;
        streams.reserve(static_cast<std::size_t>(stream_count));
        for (std::uint64_t index = 0; index < stream_count; ++index) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump loading canceled"};
            const auto at = static_cast<std::size_t>(index * 12);
            StreamRow row{static_cast<std::uint32_t>(u(directory.value().bytes, at, 4)),
                          static_cast<std::uint32_t>(u(directory.value().bytes, at + 4, 4)),
                          static_cast<std::uint32_t>(u(directory.value().bytes, at + 8, 4))};
            if (!extent(row.rva, row.size, storage->size()))
                return Error{ErrorCode::malformed, "Minidump stream lies outside the input"};
            if (std::find_if(streams.begin(), streams.end(), [&](const auto &existing) {
                    return existing.type == row.type && (row.type == stream_thread_list || row.type == stream_module_list ||
                        row.type == stream_memory_list || row.type == stream_exception || row.type == stream_system_info ||
                        row.type == stream_memory64_list || row.type == stream_function_table || row.type == stream_unloaded_module_list ||
                        row.type == stream_misc_info || row.type == stream_memory_info ||
                        row.type == stream_thread_info || row.type == stream_thread_names ||
                        row.type == stream_handle_data || row.type == stream_thread_ex_list ||
                        row.type == stream_handle_operations || row.type == stream_token_info || row.type == stream_system_memory_info || row.type == stream_process_vm_counters ||
                        row.type == stream_comment_a || row.type == stream_comment_w ||
                        row.type == stream_assertion_info || row.type == stream_linux_cpu_info ||
                        row.type == stream_linux_proc_status || row.type == stream_linux_lsb_release ||
                        row.type == stream_linux_cmd_line || row.type == stream_linux_environ ||
                        row.type == stream_linux_auxv || row.type == stream_linux_maps);
                }) != streams.end())
                return Error{ErrorCode::malformed, "Minidump contains duplicate standard streams"};
            streams.push_back(row);
            metadata.streams.push_back({row.type, row.size, row.rva});
        }

        std::uint64_t budget = streams.size() * sizeof(MinidumpStream);
        std::uint64_t decoded_contexts = 0, context_issue_count = 0;
        bool context_budget_reported = false;
        auto stream = [&](std::uint32_t type) -> std::optional<StreamRow> {
            auto found = std::find_if(streams.begin(), streams.end(), [&](const auto &row) { return row.type == type; });
            return found == streams.end() ? std::nullopt : std::optional<StreamRow>(*found);
        };
        for (const auto type : {stream_comment_a, stream_comment_w}) {
            if (auto comment_stream = stream(type)) {
                const auto retained = std::min<std::size_t>(comment_stream->size, max_comment_capture_bytes);
                if (budget > max_metadata_bytes - sizeof(MinidumpComment) ||
                    retained > max_metadata_bytes - budget - sizeof(MinidumpComment))
                    return Error{ErrorCode::resource_limit, "Minidump comment metadata exceeds its byte budget"};
                budget += sizeof(MinidumpComment) + retained;
                MinidumpComment comment;
                comment.stream_type = type;
                comment.stream_size = comment_stream->size;
                comment.stream_file_offset = FileOffset{comment_stream->rva};
                comment.truncated = retained < comment_stream->size;
                if (retained) {
                    auto bytes = read(*storage, comment_stream->rva, retained);
                    if (!bytes) return bytes.error();
                    comment.captured_bytes.assign(bytes.value().bytes.begin(), bytes.value().bytes.end());
                }
                if (type == stream_comment_w) {
                    comment.decoded_text = decode_utf16le_text(comment.captured_bytes);
                    if (comment.decoded_text) {
                        if (comment.decoded_text->size() > max_metadata_bytes - budget)
                            return Error{ErrorCode::resource_limit, "Decoded Minidump comment exceeds metadata byte budget"};
                        budget += comment.decoded_text->size();
                    } else {
                        metadata.diagnostics.emplace_back("Minidump Unicode comment prefix is truncated or malformed UTF-16LE; original bytes retained");
                    }
                }
                if (comment.truncated)
                    metadata.diagnostics.emplace_back("Minidump comment stream prefix retained; payload exceeds 4096-byte capture limit");
                metadata.comments.push_back(std::move(comment));
            }
        }
        if (auto proc_status = stream(stream_linux_proc_status)) {
            constexpr std::size_t max_status_capture = 1024u * 1024u;
            constexpr std::size_t max_status_fields = 4096;
            const auto retained = std::min<std::size_t>(proc_status->size, max_status_capture);
            if (budget > max_metadata_bytes - sizeof(MinidumpLinuxProcStatus) ||
                retained > max_metadata_bytes - budget - sizeof(MinidumpLinuxProcStatus))
                return Error{ErrorCode::resource_limit, "Minidump Linux proc-status metadata exceeds its byte budget"};
            budget += sizeof(MinidumpLinuxProcStatus) + retained;
            auto bytes = read(*storage, proc_status->rva, retained);
            if (!bytes) return bytes.error();
            MinidumpLinuxProcStatus parsed;
            parsed.stream_file_offset = FileOffset{proc_status->rva};
            parsed.declared_size = proc_status->size;
            parsed.complete = retained == proc_status->size;
            if (retained)
                parsed.captured_text.assign(reinterpret_cast<const char *>(bytes.value().bytes.data()), retained);
            for (std::size_t line_start = 0; line_start < retained;) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump loading canceled"};
                const auto newline = parsed.captured_text.find('\n', line_start);
                auto line_end = newline == std::string::npos ? retained : newline;
                if (line_end > line_start && parsed.captured_text[line_end - 1] == '\r') --line_end;
                const auto line = std::string_view(parsed.captured_text).substr(line_start, line_end - line_start);
                const auto colon = line.find(':');
                if (!line.empty() && colon != std::string_view::npos && colon != 0 && colon <= 128) {
                    const auto key = line.substr(0, colon);
                    const bool valid_key = std::all_of(key.begin(), key.end(), [](char ch) {
                        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                               (ch >= '0' && ch <= '9') || ch == '_';
                    });
                    auto value_begin = colon + 1;
                    while (value_begin < line.size() && (line[value_begin] == ' ' || line[value_begin] == '\t'))
                        ++value_begin;
                    auto value_end = line.size();
                    while (value_end > value_begin && (line[value_end - 1] == ' ' || line[value_end - 1] == '\t'))
                        --value_end;
                    const auto field_cost = sizeof(MinidumpLinuxProcStatusField) + key.size() +
                        (value_end - value_begin);
                    if (valid_key && value_end - value_begin <= 4096 && parsed.fields.size() < max_status_fields &&
                        budget <= max_metadata_bytes - field_cost) {
                        parsed.fields.push_back({std::string(key),
                            std::string(line.substr(value_begin, value_end - value_begin)),
                            FileOffset{std::uint64_t{proc_status->rva} + line_start}});
                        budget += field_cost;
                    } else {
                        parsed.complete = false;
                    }
                } else if (!line.empty()) {
                    parsed.complete = false;
                }
                if (newline == std::string::npos) break;
                line_start = newline + 1;
            }
            if (!parsed.complete)
                metadata.diagnostics.emplace_back("Minidump Linux proc-status stream is truncated or contains fields outside parser limits");
            metadata.linux_proc_status = std::move(parsed);
        }
        constexpr std::array linux_text_stream_types{
            stream_linux_cpu_info, stream_linux_lsb_release, stream_linux_cmd_line,
            stream_linux_environ, stream_linux_auxv, stream_linux_maps};
        constexpr std::size_t max_linux_text_capture = 1024u * 1024u;
        for (const auto type : linux_text_stream_types) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump loading canceled"};
            auto row = stream(type);
            if (!row) continue;
            const auto retained = std::min<std::size_t>(row->size, max_linux_text_capture);
            if (budget > max_metadata_bytes - sizeof(MinidumpLinuxTextStream) ||
                retained > max_metadata_bytes - budget - sizeof(MinidumpLinuxTextStream))
                return Error{ErrorCode::resource_limit, "Minidump Linux text-stream metadata exceeds its byte budget"};
            budget += sizeof(MinidumpLinuxTextStream) + retained;
            MinidumpLinuxTextStream parsed;
            parsed.stream_type = type;
            parsed.declared_size = row->size;
            parsed.stream_file_offset = FileOffset{row->rva};
            parsed.truncated = retained < row->size;
            if (retained) {
                auto bytes = read(*storage, row->rva, retained);
                if (!bytes) return bytes.error();
                parsed.captured_bytes.assign(bytes.value().bytes.begin(), bytes.value().bytes.end());
            }
            if (type == stream_linux_maps) {
                std::size_t cursor = 0;
                std::uint64_t previous_end = 0;
                while (cursor < parsed.captured_bytes.size()) {
                    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump Linux maps parsing canceled"};
                    const auto begin = cursor;
                    while (cursor < parsed.captured_bytes.size() && parsed.captured_bytes[cursor] != std::byte{'\n'}) ++cursor;
                    auto length = cursor - begin;
                    if (cursor < parsed.captured_bytes.size()) ++cursor;
                    if (length && parsed.captured_bytes[begin + length - 1] == std::byte{'\r'}) --length;
                    if (!length) continue;
                    if (length > 4096 || parsed.memory_maps.size() >= max_memory_regions) {
                        parsed.maps_complete = false;
                        break;
                    }
                    const auto *text = reinterpret_cast<const char *>(parsed.captured_bytes.data() + begin);
                    MinidumpLinuxMemoryMap map;
                    if (!parse_linux_map_line(std::string_view(text, length),
                                              std::uint64_t{row->rva} + begin, map) ||
                        (!parsed.memory_maps.empty() && map.start < previous_end)) {
                        parsed.maps_complete = false;
                        continue;
                    }
                    const auto row_cost = sizeof(MinidumpLinuxMemoryMap) + map.permissions.size() + map.path.size();
                    if (row_cost > max_metadata_bytes - std::min<std::uint64_t>(budget, max_metadata_bytes)) {
                        parsed.maps_complete = false;
                        break;
                    }
                    budget += row_cost;
                    previous_end = map.end;
                    parsed.memory_maps.push_back(std::move(map));
                }
                if (parsed.truncated) parsed.maps_complete = false;
                if (!parsed.maps_complete)
                    metadata.diagnostics.emplace_back("Minidump Linux maps stream has truncated or invalid rows; raw bytes remain available");
            }
            if (parsed.truncated)
                metadata.diagnostics.emplace_back("Minidump Breakpad Linux text stream prefix retained; payload exceeds 1 MiB capture limit");
            metadata.linux_text_streams.push_back(std::move(parsed));
        }
        if (auto assertion = stream(stream_assertion_info)) {
            constexpr std::uint32_t assertion_size = 776;
            if (assertion->size < assertion_size)
                return Error{ErrorCode::malformed, "Minidump assertion-info stream is truncated"};
            if (budget > max_metadata_bytes - sizeof(MinidumpAssertionInfo) - assertion_size)
                return Error{ErrorCode::resource_limit, "Minidump assertion metadata exceeds its byte budget"};
            budget += sizeof(MinidumpAssertionInfo) + assertion_size;
            auto bytes = read(*storage, assertion->rva, assertion_size);
            if (!bytes) return bytes.error();
            MinidumpAssertionInfo parsed;
            auto expression = fixed_utf16(std::span(bytes.value().bytes).subspan(0, 256), budget);
            auto function = fixed_utf16(std::span(bytes.value().bytes).subspan(256, 256), budget);
            auto file = fixed_utf16(std::span(bytes.value().bytes).subspan(512, 256), budget);
            if (!expression) return expression.error();
            if (!function) return function.error();
            if (!file) return file.error();
            parsed.expression = std::move(expression.value());
            parsed.function = std::move(function.value());
            parsed.file = std::move(file.value());
            parsed.line = static_cast<std::uint32_t>(u(bytes.value().bytes, 768, 4));
            parsed.type = static_cast<std::uint32_t>(u(bytes.value().bytes, 772, 4));
            parsed.stream_file_offset = FileOffset{assertion->rva};
            metadata.assertion = std::move(parsed);
        }
        if (auto counters = stream(stream_process_vm_counters)) {
            constexpr std::uint32_t revision1_size = 80, revision2_size = 152;
            constexpr std::uint32_t max_counter_stream_size = 4096;
            if (counters->size < 2)
                return Error{ErrorCode::malformed, "Minidump ProcessVmCounters stream is truncated before its revision"};
            auto revision_bytes = read(*storage, counters->rva, 2);
            if (!revision_bytes) return revision_bytes.error();
            const auto revision = static_cast<std::uint16_t>(u(revision_bytes.value().bytes, 0, 2));
            const auto required_size = revision == 1 ? revision1_size : revision == 2 ? revision2_size : 0;
            if (!required_size) {
                metadata.diagnostics.emplace_back("Minidump ProcessVmCounters stream uses an unsupported revision; raw stream extent is retained");
            } else if (counters->size < required_size) {
                return Error{ErrorCode::malformed, "Minidump ProcessVmCounters stream is truncated for its declared revision"};
            } else if (counters->size > max_counter_stream_size) {
                return Error{ErrorCode::resource_limit, "Minidump ProcessVmCounters stream exceeds its 4096-byte validation limit"};
            } else {
                const auto retained_size = sizeof(MinidumpVmCounters);
                if (budget > max_metadata_bytes - required_size ||
                    retained_size > max_metadata_bytes - budget - required_size)
                    return Error{ErrorCode::resource_limit, "Minidump VM counter metadata exceeds its byte budget"};
                budget += required_size + retained_size;
                auto bytes = read(*storage, counters->rva, required_size);
                if (!bytes) return bytes.error();
                MinidumpVmCounters parsed;
                parsed.revision = revision;
                parsed.flags = revision == 2 ? static_cast<std::uint16_t>(u(bytes.value().bytes, 2, 2)) : 0;
                parsed.page_fault_count = static_cast<std::uint32_t>(u(bytes.value().bytes, 4, 4));
                parsed.counter_count = revision == 1 ? 9 : 18;
                parsed.stream_size = counters->size;
                parsed.stream_file_offset = FileOffset{counters->rva};
                for (std::size_t index = 0; index < parsed.counter_count; ++index)
                    parsed.counters[index] = u(bytes.value().bytes, 8 + index * 8, 8);
                metadata.vm_counters = std::move(parsed);
            }
        }
        if (auto function_tables = stream(stream_function_table)) {
            constexpr std::uint64_t header_min = 24, descriptor_min = 32;
            constexpr std::uint64_t max_header = 4096, max_descriptor = 4096;
            constexpr std::uint64_t max_native_descriptor = 4096, max_function_entry = 4096;
            constexpr std::uint64_t max_table_count = 65536;
            if (function_tables->size < header_min)
                return Error{ErrorCode::malformed, "Minidump FunctionTable stream header is truncated"};
            auto header = read(*storage, function_tables->rva, static_cast<std::size_t>(header_min));
            if (!header) return header.error();
            const auto header_size = u(header.value().bytes, 0, 4);
            const auto descriptor_size = u(header.value().bytes, 4, 4);
            const auto native_descriptor_size = u(header.value().bytes, 8, 4);
            const auto function_entry_size = u(header.value().bytes, 12, 4);
            const auto table_count = u(header.value().bytes, 16, 4);
            const auto header_align_pad = u(header.value().bytes, 20, 4);
            if (header_size < header_min || header_size > max_header || header_size > function_tables->size ||
                descriptor_size < descriptor_min || descriptor_size > max_descriptor ||
                native_descriptor_size > max_native_descriptor || function_entry_size > max_function_entry ||
                header_align_pad > max_header || header_align_pad > function_tables->size - header_size ||
                table_count > max_table_count)
                return Error{ErrorCode::malformed, "Minidump FunctionTable header sizes or table count are invalid"};
            if (budget > max_metadata_bytes ||
                sizeof(MinidumpFunctionTableList) > max_metadata_bytes - budget ||
                table_count > (max_metadata_bytes - budget - sizeof(MinidumpFunctionTableList)) /
                                  sizeof(MinidumpFunctionTable))
                return Error{ErrorCode::resource_limit, "Minidump function-table metadata exceeds its byte budget"};
            MinidumpFunctionTableList parsed;
            parsed.stream_file_offset = FileOffset{function_tables->rva};
            parsed.stream_size = function_tables->size;
            parsed.header_size = static_cast<std::uint32_t>(header_size);
            parsed.descriptor_size = static_cast<std::uint32_t>(descriptor_size);
            parsed.native_descriptor_size = static_cast<std::uint32_t>(native_descriptor_size);
            parsed.function_entry_size = static_cast<std::uint32_t>(function_entry_size);
            parsed.align_pad_size = static_cast<std::uint32_t>(header_align_pad);
            parsed.tables.reserve(static_cast<std::size_t>(table_count));
            const std::uint64_t stream_begin = function_tables->rva;
            const std::uint64_t stream_end = stream_begin + function_tables->size;
            std::uint64_t cursor = stream_begin + header_size + header_align_pad;
            for (std::uint64_t index = 0; index < table_count; ++index) {
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Minidump FunctionTable decoding canceled"};
                if (!extent(cursor, descriptor_size, stream_end))
                    return Error{ErrorCode::malformed, "Minidump FunctionTable descriptor lies outside its stream"};
                auto descriptor = read(*storage, cursor, static_cast<std::size_t>(descriptor_min));
                if (!descriptor) return descriptor.error();
                MinidumpFunctionTable table;
                table.minimum_address = u(descriptor.value().bytes, 0, 8);
                table.maximum_address = u(descriptor.value().bytes, 8, 8);
                table.base_address = u(descriptor.value().bytes, 16, 8);
                table.entry_count = static_cast<std::uint32_t>(u(descriptor.value().bytes, 24, 4));
                table.align_pad_size = static_cast<std::uint32_t>(u(descriptor.value().bytes, 28, 4));
                table.descriptor_file_offset = FileOffset{cursor};
                if (table.minimum_address > table.maximum_address ||
                    table.align_pad_size > max_header ||
                    (table.entry_count && !function_entry_size))
                    return Error{ErrorCode::malformed, "Minidump FunctionTable descriptor range or entry layout is invalid"};
                cursor += descriptor_size;
                table.native_descriptor_file_offset = FileOffset{cursor};
                if (!extent(cursor, native_descriptor_size, stream_end))
                    return Error{ErrorCode::malformed, "Minidump FunctionTable native descriptor lies outside its stream"};
                cursor += native_descriptor_size;
                table.entries_file_offset = FileOffset{cursor};
                const auto entries_size = std::uint64_t{table.entry_count} * function_entry_size;
                if (!extent(cursor, entries_size, stream_end))
                    return Error{ErrorCode::malformed, "Minidump FunctionTable entries lie outside its stream"};
                cursor += entries_size;
                if (!extent(cursor, table.align_pad_size, stream_end))
                    return Error{ErrorCode::malformed, "Minidump FunctionTable alignment padding lies outside its stream"};
                cursor += table.align_pad_size;
                parsed.tables.push_back(std::move(table));
            }
            budget += sizeof(MinidumpFunctionTableList) + table_count * sizeof(MinidumpFunctionTable);
            metadata.function_tables = std::move(parsed);
        }
        if (auto memory_info = stream(stream_system_memory_info)) {
            constexpr std::uint32_t basic_info_size = 56;
            constexpr std::uint32_t file_cache_end = 120;
            constexpr std::uint32_t basic_performance_end = 152;
            constexpr std::uint16_t file_cache_valid = 0x0001;
            constexpr std::uint16_t basic_performance_valid = 0x0002;
            constexpr std::uint32_t max_system_memory_info_size = 4096;
            if (memory_info->size < 4)
                return Error{ErrorCode::malformed, "Minidump SystemMemoryInfo stream is truncated before revision and flags"};
            if (memory_info->size > max_system_memory_info_size)
                return Error{ErrorCode::resource_limit, "Minidump SystemMemoryInfo stream exceeds its 4096-byte validation limit"};
            auto prefix = read(*storage, memory_info->rva, 4);
            if (!prefix) return prefix.error();
            const auto revision = static_cast<std::uint16_t>(u(prefix.value().bytes, 0, 2));
            if (revision != 1) {
                metadata.diagnostics.emplace_back("Minidump SystemMemoryInfo stream uses an unsupported revision; raw stream extent is retained");
            } else if (memory_info->size < basic_info_size) {
                return Error{ErrorCode::malformed, "Minidump SystemMemoryInfo stream is truncated before MINIDUMP_SYSTEM_BASIC_INFORMATION"};
            } else {
                const auto flags = static_cast<std::uint16_t>(u(prefix.value().bytes, 2, 2));
                const auto required_size = (flags & basic_performance_valid) != 0 ? basic_performance_end :
                                           (flags & file_cache_valid) != 0 ? file_cache_end :
                                           std::min(memory_info->size, file_cache_end);
                if (memory_info->size < required_size)
                    return Error{ErrorCode::malformed, "Minidump SystemMemoryInfo stream is truncated before a flag-declared revision-1 group"};
                if (budget > max_metadata_bytes - required_size ||
                    sizeof(MinidumpSystemMemoryInfo) > max_metadata_bytes - budget - required_size)
                    return Error{ErrorCode::resource_limit, "Minidump system memory metadata exceeds its byte budget"};
                budget += required_size + sizeof(MinidumpSystemMemoryInfo);
                auto bytes = read(*storage, memory_info->rva, required_size);
                if (!bytes) return bytes.error();
                MinidumpSystemMemoryInfo parsed;
                parsed.revision = revision;
                parsed.flags = flags;
                parsed.timer_resolution = static_cast<std::uint32_t>(u(bytes.value().bytes, 4, 4));
                parsed.page_size = static_cast<std::uint32_t>(u(bytes.value().bytes, 8, 4));
                parsed.physical_page_count = static_cast<std::uint32_t>(u(bytes.value().bytes, 12, 4));
                parsed.lowest_physical_page = static_cast<std::uint32_t>(u(bytes.value().bytes, 16, 4));
                parsed.highest_physical_page = static_cast<std::uint32_t>(u(bytes.value().bytes, 20, 4));
                parsed.allocation_granularity = static_cast<std::uint32_t>(u(bytes.value().bytes, 24, 4));
                parsed.minimum_user_address = u(bytes.value().bytes, 28, 8);
                parsed.maximum_user_address = u(bytes.value().bytes, 36, 8);
                parsed.active_processor_affinity = u(bytes.value().bytes, 44, 8);
                parsed.processor_count = static_cast<std::uint32_t>(u(bytes.value().bytes, 52, 4));
                if (required_size >= file_cache_end) {
                    MinidumpSystemFileCacheInfo cache;
                    cache.current_size = u(bytes.value().bytes, 56, 8);
                    cache.peak_size = u(bytes.value().bytes, 64, 8);
                    cache.page_fault_count = static_cast<std::uint32_t>(u(bytes.value().bytes, 72, 4));
                    cache.minimum_working_set = u(bytes.value().bytes, 80, 8);
                    cache.maximum_working_set = u(bytes.value().bytes, 88, 8);
                    cache.current_size_including_transition_pages = u(bytes.value().bytes, 96, 8);
                    cache.peak_size_including_transition_pages = u(bytes.value().bytes, 104, 8);
                    cache.transition_repurpose_count = static_cast<std::uint32_t>(u(bytes.value().bytes, 112, 4));
                    cache.flags = static_cast<std::uint32_t>(u(bytes.value().bytes, 116, 4));
                    cache.transition_repurpose_count_valid = (flags & file_cache_valid) != 0;
                    parsed.file_cache = cache;
                }
                if ((flags & basic_performance_valid) != 0) {
                    MinidumpSystemBasicPerformanceInfo performance;
                    performance.available_pages = u(bytes.value().bytes, 120, 8);
                    performance.committed_pages = u(bytes.value().bytes, 128, 8);
                    performance.commit_limit = u(bytes.value().bytes, 136, 8);
                    performance.peak_commitment = u(bytes.value().bytes, 144, 8);
                    parsed.basic_performance = performance;
                }
                parsed.stream_size = memory_info->size;
                parsed.stream_file_offset = FileOffset{memory_info->rva};
                metadata.system_memory_info = std::move(parsed);
            }
        }
        if (auto sys = stream(stream_system_info)) {
            if (sys->size < 56) return Error{ErrorCode::malformed, "Minidump SystemInfo stream is truncated"};
            auto bytes = read(*storage, sys->rva, 56);
            if (!bytes) return bytes.error();
            MinidumpSystemInfo info;
            info.processor_architecture = static_cast<std::uint16_t>(u(bytes.value().bytes, 0, 2));
            info.processor_level = static_cast<std::uint16_t>(u(bytes.value().bytes, 2, 2));
            info.processor_revision = static_cast<std::uint16_t>(u(bytes.value().bytes, 4, 2));
            info.processor_count = static_cast<std::uint8_t>(u(bytes.value().bytes, 6, 1));
            info.product_type = static_cast<std::uint8_t>(u(bytes.value().bytes, 7, 1));
            info.major_version = static_cast<std::uint32_t>(u(bytes.value().bytes, 8, 4));
            info.minor_version = static_cast<std::uint32_t>(u(bytes.value().bytes, 12, 4));
            info.build_number = static_cast<std::uint32_t>(u(bytes.value().bytes, 16, 4));
            info.platform_id = static_cast<std::uint32_t>(u(bytes.value().bytes, 20, 4));
            const auto service_pack_rva = static_cast<std::uint32_t>(u(bytes.value().bytes, 24, 4));
            info.suite_mask = static_cast<std::uint16_t>(u(bytes.value().bytes, 28, 2));
            info.cpu_information.assign(bytes.value().bytes.begin() + 32, bytes.value().bytes.end());
            info.cpu_information_file_offset = FileOffset{std::uint64_t(sys->rva) + 32};
            if (info.processor_architecture == 0 || info.processor_architecture == 9) {
                MinidumpSystemInfo::X86CpuInfo cpu;
                for (std::size_t index = 0; index < cpu.vendor_id.size(); ++index)
                    cpu.vendor_id[index] = static_cast<char>(std::to_integer<unsigned char>(bytes.value().bytes[32 + index]));
                cpu.version_information = static_cast<std::uint32_t>(u(bytes.value().bytes, 44, 4));
                cpu.feature_information = static_cast<std::uint32_t>(u(bytes.value().bytes, 48, 4));
                cpu.amd_extended_cpu_features = static_cast<std::uint32_t>(u(bytes.value().bytes, 52, 4));
                cpu.source_file_offset = FileOffset{std::uint64_t(sys->rva) + 32};
                info.x86_cpu_info = cpu;
            }
            metadata.processor_architecture = info.processor_architecture;
            metadata.processor_count = info.processor_count;
            if (service_pack_rva) {
                auto service_pack = utf8(service_pack_rva, *storage, budget);
                if (service_pack) info.service_pack = std::move(service_pack.value());
                else metadata.diagnostics.emplace_back("Minidump SystemInfo service-pack string is invalid: " + service_pack.error().message);
            }
            metadata.system_info = std::move(info);
        } else metadata.diagnostics.emplace_back("Minidump has no SystemInfo stream; decode architecture is unknown");

        // Linux auxv records use the target process's native ElfW(auxv_t)
        // width. Keep the bytes regardless, and decode only architectures with
        // an unambiguous width from the captured SystemInfo stream.
        constexpr std::size_t max_auxv_entries = 4096;
        for (auto &linux_stream : metadata.linux_text_streams) {
            if (linux_stream.stream_type != stream_linux_auxv) continue;
            const auto architecture = metadata.processor_architecture;
            const std::uint8_t word_size = (architecture == 9 || architecture == 12 || architecture == 0x8003)
                ? 8 : (architecture == 0 || architecture == 5 ? 4 : 0);
            linux_stream.auxiliary_values_complete = !linux_stream.truncated && word_size != 0;
            if (!word_size) {
                metadata.diagnostics.emplace_back("Minidump Linux auxv retained raw because target word width is unknown");
                continue;
            }
            const auto record_size = static_cast<std::size_t>(word_size) * 2;
            const auto &bytes = linux_stream.captured_bytes;
            const auto complete_bytes = bytes.size() - bytes.size() % record_size;
            if (complete_bytes != bytes.size()) linux_stream.auxiliary_values_complete = false;
            bool terminated = false;
            for (std::size_t offset = 0; offset < complete_bytes; offset += record_size) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump Linux auxv parsing canceled"};
                if (terminated) {
                    const auto trailing = std::span(bytes).subspan(offset, record_size);
                    if (std::any_of(trailing.begin(), trailing.end(), [](std::byte byte) { return byte != std::byte{}; }))
                        linux_stream.auxiliary_values_complete = false;
                    continue;
                }
                if (linux_stream.auxiliary_values.size() >= max_auxv_entries) {
                    linux_stream.auxiliary_values_complete = false;
                    break;
                }
                const auto entry_cost = sizeof(MinidumpLinuxAuxvEntry);
                if (budget > max_metadata_bytes - entry_cost)
                    return Error{ErrorCode::resource_limit, "Minidump Linux auxv metadata exceeds its byte budget"};
                const auto type = u(bytes, offset, word_size);
                const auto value = u(bytes, offset + word_size, word_size);
                linux_stream.auxiliary_values.push_back({type, value,
                    FileOffset{linux_stream.stream_file_offset.value + offset}, word_size});
                budget += entry_cost;
                if (type == 0) {
                    terminated = true;
                    if (value != 0) linux_stream.auxiliary_values_complete = false;
                }
            }
            if (!terminated) linux_stream.auxiliary_values_complete = false;
            if (!linux_stream.auxiliary_values_complete)
                metadata.diagnostics.emplace_back("Minidump Linux auxv has unknown width, truncated, malformed, or exceeds parser limits; raw bytes remain available");
        }

        std::vector<minidump_detail::XstateFeatureInfo> xstate_features;
        std::uint32_t xstate_context_size = 0;
        if (auto misc = stream(stream_misc_info)) {
            if (misc->size < 4) {
                metadata.diagnostics.emplace_back("Minidump MiscInfo stream is truncated before SizeOfInfo");
            } else {
                auto size_bytes = read(*storage, misc->rva, 4);
                if (!size_bytes) return size_bytes.error();
                const auto declared = static_cast<std::size_t>(u(size_bytes.value().bytes, 0, 4));
                if (declared < 4 || declared > misc->size) {
                    metadata.diagnostics.emplace_back("Minidump MiscInfo SizeOfInfo is inconsistent with its stream extent");
                } else {
                    if (declared < 8) {
                        metadata.diagnostics.emplace_back("Minidump MiscInfo is too short to contain Flags1 process metadata");
                    } else {
                        constexpr std::size_t process_id_size = 12, process_times_size = 24,
                                              processor_power_size = 44;
                        const auto flags_view = read(*storage, misc->rva, 8);
                        if (!flags_view) return flags_view.error();
                        const auto flags = static_cast<std::uint32_t>(u(flags_view.value().bytes, 4, 4));
                        std::size_t required_prefix = 8;
                        if (flags & misc_info_process_id) required_prefix = std::max(required_prefix, process_id_size);
                        if (flags & misc_info_process_times) required_prefix = std::max(required_prefix, process_times_size);
                        if (flags & misc_info_processor_power) required_prefix = std::max(required_prefix, processor_power_size);
                        const auto captured = std::min(declared, required_prefix);
                        constexpr auto process_info_cost = sizeof(MinidumpProcessInfo);
                        if (captured > max_metadata_bytes || process_info_cost > max_metadata_bytes - captured ||
                            budget > max_metadata_bytes - captured - process_info_cost)
                            return Error{ErrorCode::resource_limit, "Minidump metadata exceeds its byte budget"};
                        budget += captured + process_info_cost;
                        auto base = read(*storage, misc->rva, captured);
                        if (!base) return base.error();
                        MinidumpProcessInfo process;
                        process.flags = static_cast<std::uint32_t>(u(base.value().bytes, 4, 4));
                        process.declared_size = static_cast<std::uint32_t>(declared);
                        process.stream_file_offset = FileOffset{misc->rva};
                        if (process.flags & misc_info_process_id) {
                            if (declared >= process_id_size) process.process_id = static_cast<std::uint32_t>(u(base.value().bytes, 8, 4));
                            else metadata.diagnostics.emplace_back("Minidump MiscInfo declares process ID metadata without its field");
                        }
                        if (process.flags & misc_info_process_times) {
                            if (declared >= process_times_size) {
                                process.process_create_time = static_cast<std::uint32_t>(u(base.value().bytes, 12, 4));
                                process.process_user_time = static_cast<std::uint32_t>(u(base.value().bytes, 16, 4));
                                process.process_kernel_time = static_cast<std::uint32_t>(u(base.value().bytes, 20, 4));
                            } else metadata.diagnostics.emplace_back("Minidump MiscInfo declares process timing metadata without all three fields");
                        }
                        if (process.flags & misc_info_processor_power) {
                            if (declared >= processor_power_size) {
                                process.processor_max_mhz = static_cast<std::uint32_t>(u(base.value().bytes, 24, 4));
                                process.processor_current_mhz = static_cast<std::uint32_t>(u(base.value().bytes, 28, 4));
                                process.processor_mhz_limit = static_cast<std::uint32_t>(u(base.value().bytes, 32, 4));
                                process.processor_max_idle_state = static_cast<std::uint32_t>(u(base.value().bytes, 36, 4));
                                process.processor_current_idle_state = static_cast<std::uint32_t>(u(base.value().bytes, 40, 4));
                                for (std::size_t index = 0; index < process.processor_power_field_offsets.size(); ++index)
                                    process.processor_power_field_offsets[index] = FileOffset{std::uint64_t{misc->rva} + 24 + index * 4};
                            } else metadata.diagnostics.emplace_back("Minidump MiscInfo declares processor power metadata without all five fields");
                        }
                        metadata.process_info = process;
                    }
                }
                if (declared >= misc_info5_xstate_offset + xstate_config_feature_size) {
                    auto info = read(*storage, misc->rva, misc_info5_xstate_offset + xstate_config_feature_size);
                    if (!info) return info.error();
                    const auto info_size = static_cast<std::size_t>(u(info.value().bytes, misc_info5_xstate_offset, 4));
                    xstate_context_size = static_cast<std::uint32_t>(u(info.value().bytes, misc_info5_xstate_offset + 4, 4));
                    const auto enabled = u(info.value().bytes, misc_info5_xstate_offset + 8, 8);
                    bool valid = info_size >= xstate_config_feature_size &&
                                 info_size <= declared - misc_info5_xstate_offset &&
                                 xstate_context_size != 0 && xstate_context_size <= 1024u * 1024u;
                    for (std::size_t index = 0; index < 64; ++index) {
                        if (!(enabled & (std::uint64_t{1} << index))) continue;
                        const auto at = misc_info5_xstate_offset + 16 + index * 8;
                        const auto offset = static_cast<std::uint32_t>(u(info.value().bytes, at, 4));
                        const auto size = static_cast<std::uint32_t>(u(info.value().bytes, at + 4, 4));
                        if (!size || offset > xstate_context_size || size > xstate_context_size - offset) {
                            valid = false;
                            break;
                        }
                        xstate_features.push_back({static_cast<std::uint8_t>(index), offset, size});
                    }
                    if (!valid) {
                        xstate_features.clear();
                        xstate_context_size = 0;
                        metadata.diagnostics.emplace_back("Minidump MiscInfo5 XSTATE feature map is inconsistent or exceeds its validation bounds");
                    }
                }
            }
        }

        auto context_at = [&](std::uint32_t size, std::uint32_t rva)
            -> Result<std::optional<MinidumpContext>> {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump context decoding canceled"};
            if (!size) return std::optional<MinidumpContext>{};
            if (!rva || !extent(rva, size, storage->size()))
                return Error{ErrorCode::malformed, "Minidump nonempty context has a null or out-of-file RVA"};
            if (decoded_contexts >= max_decoded_contexts) {
                if (!context_budget_reported) {
                    metadata.diagnostics.emplace_back("Minidump thread-context decode limit reached; remaining contexts retain only their source extents");
                    context_budget_reported = true;
                }
                return std::optional<MinidumpContext>{};
            }
            const auto prefix = std::max<std::size_t>(minidump_detail::context_prefix_size(metadata.processor_architecture),
                                                       metadata.processor_architecture == 12 ? 1232 : 0);
            std::size_t capture_size = std::min<std::size_t>(size, prefix);
            auto initial = read(*storage, rva, capture_size);
            if (!initial) return initial.error();
            if (metadata.processor_architecture == 9 && initial.value().bytes.size() >= 52 &&
                (u(initial.value().bytes, 48, 4) & 0x40u) && xstate_context_size) {
                constexpr std::uint64_t amd64_xsave_base = 256;
                for (const auto &feature : xstate_features) {
                    if (feature.index < 2) continue;
                    const std::uint64_t end = amd64_xsave_base + feature.offset + feature.size;
                    if (end <= size && end <= prefix + max_xstate_context_bytes)
                        capture_size = std::max(capture_size, static_cast<std::size_t>(end));
                }
            }
            auto data = capture_size == initial.value().bytes.size()
                ? std::move(initial)
                : read(*storage, rva, capture_size);
            if (!data) return data.error();
            const auto selection = select_compatible_context_architecture(metadata.processor_architecture, size,
                                                                           data.value().bytes);
            MinidumpContext decoded;
            if (selection.ambiguous) {
                decoded.processor_architecture = metadata.processor_architecture;
                decoded.source_rva = rva;
                decoded.source_size = size;
                decoded.captured_prefix.assign(data.value().bytes.begin(), data.value().bytes.end());
                decoded.status = MinidumpContextStatus::architecture_mismatch;
                decoded.diagnostics.emplace_back("Context layout signatures match multiple supported architectures; captured bytes retained without register interpretation");
            } else {
                decoded = minidump_detail::decode_context(selection.architecture, data.value().bytes, rva, size,
                                                          xstate_context_size, xstate_features);
                if (selection.architecture != metadata.processor_architecture) {
                    decoded.diagnostics.emplace_back(selection.architecture == 0
                        ? "WOW64-compatible x86 context selected from its exact 716-byte layout and x86 ContextFlags; SystemInfo architecture differs"
                        : "AMD64-compatible 1232-byte context selected from its AMD64 ContextFlags; ARM64EC versus x64 emulation is not distinguishable from this context alone");
                }
            }
            auto context = std::move(decoded);
            if (context.status != MinidumpContextStatus::decoded) ++context_issue_count;
            std::uint64_t cost = sizeof(MinidumpContext) + context.registers.size() * sizeof(MinidumpRegister);
            cost += context.captured_prefix.size();
            for (const auto &reg : context.registers) cost += reg.name.size() + reg.bytes.size();
            for (const auto &diagnostic : context.diagnostics) cost += diagnostic.size();
            if (budget > max_metadata_bytes || cost > max_metadata_bytes - budget)
                return Error{ErrorCode::resource_limit, "Minidump register contexts exceed the metadata budget"};
            budget += cost;
            ++decoded_contexts;
            return std::optional<MinidumpContext>(std::move(context));
        };

        std::vector<Region> regions;
        if (auto list = stream(stream_memory_list)) {
            if (list->size < 4) return Error{ErrorCode::malformed, "Minidump MemoryList stream is truncated"};
            auto count_bytes = read(*storage, list->rva, 4);
            if (!count_bytes) return count_bytes.error();
            const auto count = u(count_bytes.value().bytes, 0, 4);
            if (count > max_memory_regions || regions.size() + count > max_memory_regions ||
                count > (list->size - 4) / 16)
                return Error{ErrorCode::resource_limit, "Minidump memory range count exceeds stream bounds"};
            auto bytes = read(*storage, list->rva, static_cast<std::size_t>(4 + count * 16));
            if (!bytes) return bytes.error();
            regions.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump loading canceled"};
                const auto at = static_cast<std::size_t>(4 + i * 16);
                const auto base = u(bytes.value().bytes, at, 8);
                const auto size = u(bytes.value().bytes, at + 8, 4);
                const auto rva = u(bytes.value().bytes, at + 12, 4);
                if (!size || !extent(rva, size, storage->size()) || base > UINT64_MAX - size)
                    return Error{ErrorCode::malformed, "Minidump memory descriptor has an invalid extent"};
                regions.push_back({base, size, rva});
            }
            budget += count * sizeof(Region);
        }
        if (auto list = stream(stream_memory64_list)) {
            if (list->size < 16) return Error{ErrorCode::malformed, "Minidump Memory64List stream is truncated"};
            auto header_bytes = read(*storage, list->rva, 16);
            if (!header_bytes) return header_bytes.error();
            const auto count = u(header_bytes.value().bytes, 0, 8);
            const auto base_rva = u(header_bytes.value().bytes, 8, 8);
            if (count > max_memory_regions || regions.size() + count > max_memory_regions ||
                count > (list->size - 16) / 16)
                return Error{ErrorCode::resource_limit, "Minidump Memory64 range count exceeds stream bounds"};
            auto bytes = read(*storage, list->rva, static_cast<std::size_t>(16 + count * 16));
            if (!bytes) return bytes.error();
            if (!extent(base_rva, 0, storage->size()))
                return Error{ErrorCode::malformed, "Minidump Memory64 payload starts outside the input"};
            std::uint64_t cursor = base_rva;
            regions.reserve(regions.size() + static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump loading canceled"};
                const auto at = static_cast<std::size_t>(16 + i * 16);
                const auto base = u(bytes.value().bytes, at, 8);
                const auto size = u(bytes.value().bytes, at + 8, 8);
                if (!size || !extent(cursor, size, storage->size()) || base > UINT64_MAX - size || cursor > UINT64_MAX - size)
                    return Error{ErrorCode::malformed, "Minidump Memory64 descriptor has an invalid extent"};
                regions.push_back({base, size, cursor});
                cursor += size;
            }
            budget += count * sizeof(Region);
        }
        if (regions.size() > max_memory_regions || budget > max_metadata_bytes)
            return Error{ErrorCode::resource_limit, "Minidump memory metadata exceeds configured limits"};

        std::vector<Protection> protections;
        if (auto list = stream(stream_memory_info)) {
            if (list->size < 16) return Error{ErrorCode::malformed, "Minidump MemoryInfoList stream is truncated"};
            auto header_bytes = read(*storage, list->rva, 16);
            if (!header_bytes) return header_bytes.error();
            const auto header_size = u(header_bytes.value().bytes, 0, 4);
            const auto entry_size = u(header_bytes.value().bytes, 4, 4);
            const auto count = u(header_bytes.value().bytes, 8, 8);
            if (header_size < 16 || header_size > 4096 || entry_size < 48 || entry_size > 4096 ||
                !extent(0, header_size, list->size) ||
                count > max_memory_regions || count > (list->size - header_size) / entry_size)
                return Error{ErrorCode::malformed, "Minidump MemoryInfoList header or entries are invalid"};
            const auto table_size = header_size + count * entry_size;
            if (table_size > max_metadata_bytes)
                return Error{ErrorCode::resource_limit, "Minidump MemoryInfoList exceeds its metadata budget"};
            auto bytes = read(*storage, list->rva, static_cast<std::size_t>(table_size));
            if (!bytes) return bytes.error();
            protections.reserve(static_cast<std::size_t>(count));
            metadata.memory_info.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                const auto at = static_cast<std::size_t>(header_size + i * entry_size);
                const auto base = u(bytes.value().bytes, at, 8);
                const auto allocation_base = u(bytes.value().bytes, at + 8, 8);
                const auto allocation_protect = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 16, 4));
                const auto size = u(bytes.value().bytes, at + 24, 8);
                const auto state = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 32, 4));
                const auto protect = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 36, 4));
                const auto type = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 40, 4));
                if (!size || base > UINT64_MAX - size)
                    return Error{ErrorCode::malformed, "Minidump memory information has an invalid address range"};
                protections.push_back({base, base + size, allocation_base, allocation_protect, protect, state, type});
                metadata.memory_info.push_back({base, allocation_base, size, allocation_protect, protect,
                    state, type, FileOffset{std::uint64_t{list->rva} + at}});
            }
            std::sort(protections.begin(), protections.end(), [](const auto &a, const auto &b) { return a.begin < b.begin; });
            for (std::size_t i = 1; i < protections.size(); ++i)
                if (protections[i].begin < protections[i - 1].end)
                    return Error{ErrorCode::malformed, "Minidump memory information ranges overlap"};
            budget += count * (sizeof(Protection) + sizeof(MinidumpMemoryInfo));
        }

        if (auto list = stream(stream_module_list)) {
            if (list->size < 4) return Error{ErrorCode::malformed, "Minidump ModuleList stream is truncated"};
            auto count_bytes = read(*storage, list->rva, 4);
            if (!count_bytes) return count_bytes.error();
            const auto count = u(count_bytes.value().bytes, 0, 4);
            constexpr std::size_t record_size = 108;
            if (count > max_modules || count > (list->size - 4) / record_size)
                return Error{ErrorCode::resource_limit, "Minidump module count exceeds stream bounds"};
            auto bytes = read(*storage, list->rva, static_cast<std::size_t>(4 + count * record_size));
            if (!bytes) return bytes.error();
            metadata.modules.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump loading canceled"};
                const auto at = static_cast<std::size_t>(4 + i * record_size);
                MinidumpModule module;
                module.image_base = u(bytes.value().bytes, at, 8);
                module.image_size = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 8, 4));
                module.checksum = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 12, 4));
                module.timestamp = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 16, 4));
                auto name = utf8(static_cast<std::uint32_t>(u(bytes.value().bytes, at + 20, 4)), *storage, budget);
                if (!name) return name.error();
                module.name = std::move(name.value());
                module.version_info_file_offset = {std::uint64_t{list->rva} + at + 24};
                for (std::size_t field = 0; field < module.version_info.size(); ++field)
                    module.version_info[field] = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 24 + field * 4, 4));
                module.version_info_signature_valid = module.version_info[0] == 0xfeef04bd;
                module.cv_record_size = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 76, 4));
                module.cv_record_rva = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 80, 4));
                if (module.image_size && module.image_base > UINT64_MAX - module.image_size)
                    return Error{ErrorCode::overflow, "Minidump module image range overflows"};
                if (module.cv_record_size && !extent(module.cv_record_rva, module.cv_record_size, storage->size()))
                    return Error{ErrorCode::malformed, "Minidump module CodeView record is outside the input"};
                if (module.cv_record_size) {
                    auto parsed = parse_codeview(module, *storage, budget);
                    if (!parsed) return parsed.error();
                }
                metadata.modules.push_back(std::move(module));
            }
            budget += count * sizeof(MinidumpModule);
        }

        if (auto list = stream(stream_unloaded_module_list)) {
            if (list->size < 12)
                return Error{ErrorCode::malformed, "Minidump UnloadedModuleList stream header is truncated"};
            auto header = read(*storage, list->rva, 12);
            if (!header) return header.error();
            const auto header_size = u(header.value().bytes, 0, 4);
            const auto entry_size = u(header.value().bytes, 4, 4);
            const auto count = u(header.value().bytes, 8, 4);
            if (header_size < 12 || header_size > 4096 || entry_size < 24 || entry_size > 4096 ||
                header_size > list->size || count > max_modules ||
                count > (list->size - header_size) / entry_size)
                return Error{ErrorCode::malformed, "Minidump UnloadedModuleList header or entries are invalid"};
            const auto table_size = header_size + count * entry_size;
            if (table_size > max_metadata_bytes || budget > max_metadata_bytes ||
                count > (max_metadata_bytes - budget) / sizeof(MinidumpUnloadedModule))
                return Error{ErrorCode::resource_limit, "Minidump unloaded-module metadata exceeds its byte budget"};
            auto bytes = read(*storage, list->rva, static_cast<std::size_t>(table_size));
            if (!bytes) return bytes.error();
            metadata.unloaded_modules.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump unloaded-module parsing canceled"};
                const auto at = static_cast<std::size_t>(header_size + i * entry_size);
                MinidumpUnloadedModule module;
                module.record_file_offset = {std::uint64_t{list->rva} + at};
                module.image_base = u(bytes.value().bytes, at, 8);
                module.image_size = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 8, 4));
                module.checksum = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 12, 4));
                module.timestamp = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 16, 4));
                const auto name_rva = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 20, 4));
                if (!name_rva || (module.image_size && module.image_base > UINT64_MAX - module.image_size))
                    return Error{ErrorCode::malformed, "Minidump unloaded-module record has an invalid name or image range"};
                auto name = utf8(name_rva, *storage, budget);
                if (!name) return name.error();
                module.name_file_offset = {name_rva};
                module.name = std::move(name.value());
                metadata.unloaded_modules.push_back(std::move(module));
            }
            budget += count * sizeof(MinidumpUnloadedModule);
        }

        auto thread_list_stream = stream(stream_thread_ex_list);
        if (!thread_list_stream) thread_list_stream = stream(stream_thread_list);
        if (auto list = thread_list_stream) {
            if (list->size < 4) return Error{ErrorCode::malformed, "Minidump ThreadList stream is truncated"};
            auto count_bytes = read(*storage, list->rva, 4);
            if (!count_bytes) return count_bytes.error();
            const auto count = u(count_bytes.value().bytes, 0, 4);
            const bool extended = list->type == stream_thread_ex_list;
            constexpr std::size_t basic_record_size = 48, extended_record_size = 64;
            const std::size_t record_size = extended ? extended_record_size : basic_record_size;
            if (count > max_threads || count > (list->size - 4) / record_size)
                return Error{ErrorCode::resource_limit, "Minidump thread count exceeds stream bounds"};
            auto bytes = read(*storage, list->rva, static_cast<std::size_t>(4 + count * record_size));
            if (!bytes) return bytes.error();
            constexpr auto thread_cost = sizeof(MinidumpThread) + sizeof(std::uint32_t);
            if (budget > max_metadata_bytes || count > (max_metadata_bytes - budget) / thread_cost)
                return Error{ErrorCode::resource_limit, "Minidump thread metadata exceeds its byte budget"};
            budget += count * thread_cost;
            metadata.threads.reserve(static_cast<std::size_t>(count));
            std::vector<std::uint32_t> thread_ids;
            thread_ids.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump thread-context decoding canceled"};
                const auto at = static_cast<std::size_t>(4 + i * record_size);
                MinidumpThread thread;
                thread.record_file_offset = {std::uint64_t{list->rva} + at};
                thread.id = static_cast<std::uint32_t>(u(bytes.value().bytes, at, 4));
                if (!thread.id)
                    return Error{ErrorCode::malformed, "Minidump ThreadList has a zero thread ID"};
                thread_ids.push_back(thread.id);
                thread.suspend_count = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 4, 4));
                thread.priority_class = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 8, 4));
                thread.priority = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 12, 4));
                thread.teb = u(bytes.value().bytes, at + 16, 8);
                thread.stack_address = u(bytes.value().bytes, at + 24, 8);
                thread.stack_size = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 32, 4));
                thread.stack_rva = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 36, 4));
                thread.context_size = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 40, 4));
                thread.context_rva = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 44, 4));
                thread.extended_record = extended;
                if (extended) {
                    thread.backing_store_address = u(bytes.value().bytes, at + 48, 8);
                    thread.backing_store_size = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 56, 4));
                    thread.backing_store_rva = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 60, 4));
                }
                if ((thread.stack_size && (thread.stack_address > UINT64_MAX - thread.stack_size ||
                                           !extent(thread.stack_rva, thread.stack_size, storage->size()))) ||
                    (thread.context_size && !extent(thread.context_rva, thread.context_size, storage->size())) ||
                    (thread.backing_store_size && (thread.backing_store_address > UINT64_MAX - thread.backing_store_size ||
                                                   !extent(thread.backing_store_rva, thread.backing_store_size, storage->size()))))
                    return Error{ErrorCode::malformed, "Minidump thread stack/context/backing-store data is outside the input"};
                auto context = context_at(thread.context_size, thread.context_rva);
                if (!context) return context.error();
                thread.context = std::move(context.value());
                metadata.threads.push_back(std::move(thread));
            }
            std::sort(thread_ids.begin(), thread_ids.end());
            if (std::adjacent_find(thread_ids.begin(), thread_ids.end()) != thread_ids.end())
                return Error{ErrorCode::malformed, "Minidump ThreadList has duplicate thread IDs"};
        }

        if (auto exception = stream(stream_exception)) {
            if (exception->size < 168) return Error{ErrorCode::malformed, "Minidump Exception stream is truncated"};
            auto bytes = read(*storage, exception->rva, 168);
            if (!bytes) return bytes.error();
            MinidumpException row;
            row.record_file_offset = {exception->rva};
            row.thread_id = static_cast<std::uint32_t>(u(bytes.value().bytes, 0, 4));
            row.code = static_cast<std::uint32_t>(u(bytes.value().bytes, 8, 4));
            row.flags = static_cast<std::uint32_t>(u(bytes.value().bytes, 12, 4));
            row.record = u(bytes.value().bytes, 16, 8);
            row.address = u(bytes.value().bytes, 24, 8);
            row.parameter_count = static_cast<std::uint32_t>(u(bytes.value().bytes, 32, 4));
            if (row.parameter_count > 15)
                return Error{ErrorCode::malformed, "Minidump Exception parameter count exceeds the format limit"};
            row.parameters.reserve(row.parameter_count);
            for (std::uint32_t i = 0; i < row.parameter_count; ++i)
                row.parameters.push_back(u(bytes.value().bytes, 40 + i * 8, 8));
            row.context_size = static_cast<std::uint32_t>(u(bytes.value().bytes, 160, 4));
            row.context_rva = static_cast<std::uint32_t>(u(bytes.value().bytes, 164, 4));
            if (row.context_size && !extent(row.context_rva, row.context_size, storage->size()))
                return Error{ErrorCode::malformed, "Minidump exception context is outside the input"};
            auto context = context_at(row.context_size, row.context_rva);
            if (!context) return context.error();
            row.context = std::move(context.value());
            metadata.exception = std::move(row);
        }

        if (auto names = stream(stream_thread_names)) {
            if (names->size < 4)
                return Error{ErrorCode::malformed, "Minidump ThreadNames stream is truncated"};
            auto count_bytes = read(*storage, names->rva, 4);
            if (!count_bytes) return count_bytes.error();
            const auto count = u(count_bytes.value().bytes, 0, 4);
            constexpr std::size_t record_size = 12;
            if (count > max_threads || count > (names->size - 4) / record_size)
                return Error{ErrorCode::resource_limit, "Minidump thread-name count exceeds stream bounds"};
            auto bytes = read(*storage, names->rva, static_cast<std::size_t>(4 + count * record_size));
            if (!bytes) return bytes.error();
            constexpr std::size_t row_cost = sizeof(MinidumpThreadName) + sizeof(std::uint32_t);
            if (budget > max_metadata_bytes || count > (max_metadata_bytes - budget) / row_cost)
                return Error{ErrorCode::resource_limit, "Minidump thread-name metadata exceeds its byte budget"};
            metadata.thread_names.reserve(static_cast<std::size_t>(count));
            std::vector<std::uint32_t> thread_ids;
            thread_ids.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump thread-name decoding canceled"};
                const auto at = static_cast<std::size_t>(4 + i * record_size);
                const auto thread_id = static_cast<std::uint32_t>(u(bytes.value().bytes, at, 4));
                const auto name_rva = u(bytes.value().bytes, at + 4, 8);
                if (!thread_id || !name_rva)
                    return Error{ErrorCode::malformed, "Minidump thread-name row has a zero thread ID or string RVA"};
                auto name = utf8(name_rva, *storage, budget);
                if (!name) return name.error();
                if (budget > max_metadata_bytes || name.value().size() > max_metadata_bytes - budget)
                    return Error{ErrorCode::resource_limit, "Minidump thread names exceed the metadata byte budget"};
                budget += name.value().size();
                MinidumpThreadName row;
                row.thread_id = thread_id;
                row.name = std::move(name.value());
                row.record_file_offset = {std::uint64_t{names->rva} + at};
                row.string_file_offset = {name_rva};
                thread_ids.push_back(thread_id);
                metadata.thread_names.push_back(std::move(row));
            }
            std::sort(thread_ids.begin(), thread_ids.end());
            if (std::adjacent_find(thread_ids.begin(), thread_ids.end()) != thread_ids.end())
                return Error{ErrorCode::malformed, "Minidump ThreadNames stream has duplicate thread IDs"};
            std::sort(metadata.thread_names.begin(), metadata.thread_names.end(), [](const auto &left, const auto &right) {
                return left.thread_id < right.thread_id;
            });
            budget += count * row_cost;
        }

        if (auto info = stream(stream_thread_info)) {
            constexpr std::size_t header_size_min = 12;
            constexpr std::size_t entry_size_min = 64;
            constexpr std::size_t max_record_size = 4096;
            if (info->size < header_size_min)
                return Error{ErrorCode::malformed, "Minidump ThreadInfoList stream header is truncated"};
            auto header = read(*storage, info->rva, header_size_min);
            if (!header) return header.error();
            const auto header_size = u(header.value().bytes, 0, 4);
            const auto entry_size = u(header.value().bytes, 4, 4);
            const auto count = u(header.value().bytes, 8, 4);
            if (header_size < header_size_min || header_size > max_record_size || header_size > info->size ||
                entry_size < entry_size_min || entry_size > max_record_size ||
                count > (info->size - header_size) / entry_size)
                return Error{ErrorCode::malformed, "Minidump ThreadInfoList header or entries are invalid"};
            if (count > max_threads)
                return Error{ErrorCode::resource_limit, "Minidump thread-info count exceeds its limit"};
            constexpr std::size_t row_cost = sizeof(MinidumpThreadInfo) + sizeof(std::uint32_t);
            if (budget > max_metadata_bytes || count > (max_metadata_bytes - budget) / row_cost)
                return Error{ErrorCode::resource_limit, "Minidump thread-info metadata exceeds its byte budget"};
            const auto table_size = header_size + count * entry_size;
            if (table_size > max_metadata_bytes)
                return Error{ErrorCode::resource_limit, "Minidump ThreadInfoList byte extent exceeds its validation budget"};
            auto bytes = read(*storage, info->rva, static_cast<std::size_t>(table_size));
            if (!bytes) return bytes.error();
            metadata.thread_info.reserve(static_cast<std::size_t>(count));
            std::vector<std::uint32_t> thread_ids;
            thread_ids.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump thread-info decoding canceled"};
                const auto at = static_cast<std::size_t>(header_size + i * entry_size);
                MinidumpThreadInfo row;
                row.thread_id = static_cast<std::uint32_t>(u(bytes.value().bytes, at, 4));
                row.dump_flags = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 4, 4));
                row.dump_error = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 8, 4));
                row.exit_status = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 12, 4));
                row.create_time = u(bytes.value().bytes, at + 16, 8);
                row.exit_time = u(bytes.value().bytes, at + 24, 8);
                row.kernel_time = u(bytes.value().bytes, at + 32, 8);
                row.user_time = u(bytes.value().bytes, at + 40, 8);
                row.start_address = u(bytes.value().bytes, at + 48, 8);
                row.affinity = u(bytes.value().bytes, at + 56, 8);
                row.record_file_offset = FileOffset{std::uint64_t{info->rva} + at};
                if (!row.thread_id)
                    return Error{ErrorCode::malformed, "Minidump ThreadInfoList has a zero thread ID"};
                thread_ids.push_back(row.thread_id);
                metadata.thread_info.push_back(std::move(row));
            }
            std::sort(thread_ids.begin(), thread_ids.end());
            if (std::adjacent_find(thread_ids.begin(), thread_ids.end()) != thread_ids.end())
                return Error{ErrorCode::malformed, "Minidump ThreadInfoList has duplicate thread IDs"};
            std::sort(metadata.thread_info.begin(), metadata.thread_info.end(),
                      [](const auto &a, const auto &b) { return a.thread_id < b.thread_id; });
            budget += count * row_cost;
        }

        if (auto handles = stream(stream_handle_data)) {
            constexpr std::size_t header_size_min = 16;
            constexpr std::size_t descriptor_v1_size = 32, descriptor_v2_size = 40;
            constexpr std::size_t max_header_size = 4096;
            if (handles->size < header_size_min)
                return Error{ErrorCode::malformed, "Minidump HandleData stream header is truncated"};
            auto header = read(*storage, handles->rva, header_size_min);
            if (!header) return header.error();
            const auto header_size = u(header.value().bytes, 0, 4);
            const auto descriptor_size = u(header.value().bytes, 4, 4);
            const auto count = u(header.value().bytes, 8, 4);
            const auto reserved = u(header.value().bytes, 12, 4);
            if (header_size < header_size_min || header_size > max_header_size || header_size > handles->size ||
                (descriptor_size != descriptor_v1_size && descriptor_size != descriptor_v2_size) ||
                count > (handles->size - header_size) / descriptor_size || reserved != 0)
                return Error{ErrorCode::malformed, "Minidump HandleData header or descriptor extent is invalid"};
            if (count > max_handles)
                return Error{ErrorCode::resource_limit, "Minidump handle count exceeds its limit"};
            constexpr std::size_t row_cost = sizeof(MinidumpHandle) + sizeof(std::uint64_t);
            if (budget > max_metadata_bytes || count > (max_metadata_bytes - budget) / row_cost)
                return Error{ErrorCode::resource_limit, "Minidump handle metadata exceeds its byte budget"};
            const auto retained_handle_cost = count * row_cost;
            const auto table_size = header_size + count * descriptor_size;
            if (table_size > max_metadata_bytes)
                return Error{ErrorCode::resource_limit, "Minidump HandleData table exceeds its validation budget"};
            auto descriptors = read(*storage, handles->rva, static_cast<std::size_t>(table_size));
            if (!descriptors) return descriptors.error();
            metadata.handles.reserve(static_cast<std::size_t>(count));
            budget += retained_handle_cost;
            std::uint64_t object_info_records = 0;
            for (std::uint64_t i = 0; i < count; ++i) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump handle decoding canceled"};
                const auto at = static_cast<std::size_t>(header_size + i * descriptor_size);
                MinidumpHandle row;
                row.handle = u(descriptors.value().bytes, at, 8);
                const auto type_name_rva = static_cast<std::uint32_t>(u(descriptors.value().bytes, at + 8, 4));
                const auto object_name_rva = static_cast<std::uint32_t>(u(descriptors.value().bytes, at + 12, 4));
                row.attributes = static_cast<std::uint32_t>(u(descriptors.value().bytes, at + 16, 4));
                row.granted_access = static_cast<std::uint32_t>(u(descriptors.value().bytes, at + 20, 4));
                row.handle_count = static_cast<std::uint32_t>(u(descriptors.value().bytes, at + 24, 4));
                row.pointer_count = static_cast<std::uint32_t>(u(descriptors.value().bytes, at + 28, 4));
                row.record_file_offset = FileOffset{std::uint64_t{handles->rva} + at};
                if (descriptor_size == descriptor_v2_size) {
                    row.object_info_rva = static_cast<std::uint32_t>(u(descriptors.value().bytes, at + 32, 4));
                    row.reserved = static_cast<std::uint32_t>(u(descriptors.value().bytes, at + 36, 4));
                    if (row.reserved)
                        return Error{ErrorCode::malformed, "Minidump HandleData descriptor has nonzero Reserved0"};
                    std::unordered_set<std::uint32_t> visited_info_rvas;
                    auto info_rva = row.object_info_rva;
                    while (info_rva) {
                        if (stop.stop_requested())
                            return Error{ErrorCode::canceled, "Minidump handle object-info decoding canceled"};
                        if (row.object_information.size() >= max_handle_object_info_per_handle ||
                            object_info_records >= max_handle_object_info_records)
                            return Error{ErrorCode::resource_limit,
                                         "Minidump handle object-info chain exceeds its record limit"};
                        if (!visited_info_rvas.insert(info_rva).second)
                            return Error{ErrorCode::malformed, "Minidump handle object-info chain contains a cycle"};
                        if (!extent(info_rva, 12, storage->size()))
                            return Error{ErrorCode::malformed,
                                         "Minidump handle object-info header lies outside the input"};
                        auto info_header = read(*storage, info_rva, 12);
                        if (!info_header) return info_header.error();
                        MinidumpHandleObjectInformation info;
                        info.next_info_rva = static_cast<std::uint32_t>(u(info_header.value().bytes, 0, 4));
                        info.info_type = static_cast<std::uint32_t>(u(info_header.value().bytes, 4, 4));
                        info.size_of_info = static_cast<std::uint32_t>(u(info_header.value().bytes, 8, 4));
                        const auto data_rva = std::uint64_t{info_rva} + 12;
                        if (!extent(data_rva, info.size_of_info, storage->size()))
                            return Error{ErrorCode::malformed,
                                         "Minidump handle object-info payload lies outside the input"};
                        constexpr std::uint64_t info_record_cost = 12 + sizeof(MinidumpHandleObjectInformation);
                        const auto added_cost = info_record_cost + info.size_of_info;
                        if (added_cost > max_metadata_bytes || budget > max_metadata_bytes - added_cost)
                            return Error{ErrorCode::resource_limit,
                                         "Minidump handle object-info metadata exceeds its byte budget"};
                        info.record_file_offset = FileOffset{info_rva};
                        info.data_file_offset = FileOffset{data_rva};
                        if (info.size_of_info) {
                            auto data = read(*storage, data_rva, info.size_of_info);
                            if (!data) return data.error();
                            info.data.assign(data.value().bytes.begin(), data.value().bytes.end());
                        }
                        budget += added_cost;
                        ++object_info_records;
                        info_rva = info.next_info_rva;
                        row.object_information.push_back(std::move(info));
                    }
                }
                if (type_name_rva) {
                    auto name = utf8(type_name_rva, *storage, budget);
                    if (!name) return name.error();
                    row.type_name = std::move(name.value());
                    row.type_name_file_offset = FileOffset{type_name_rva};
                }
                if (object_name_rva) {
                    auto name = utf8(object_name_rva, *storage, budget);
                    if (!name) return name.error();
                    row.object_name = std::move(name.value());
                    row.object_name_file_offset = FileOffset{object_name_rva};
                }
                metadata.handles.push_back(std::move(row));
            }
        }

        if (auto operations = stream(stream_handle_operations)) {
            constexpr std::uint64_t header_min = 16, entry_min = 288;
            constexpr std::uint64_t max_header = 4096, max_entry = 4096, max_operations = 65536;
            if (operations->size < header_min)
                return Error{ErrorCode::malformed, "Minidump HandleOperationList header is truncated"};
            auto header = read(*storage, operations->rva, header_min);
            if (!header) return header.error();
            const auto header_size = u(header.value().bytes, 0, 4);
            const auto entry_size = u(header.value().bytes, 4, 4);
            const auto count = u(header.value().bytes, 8, 4);
            if (header_size < header_min || header_size > max_header || header_size > operations->size ||
                entry_size < entry_min || entry_size > max_entry ||
                count > (operations->size - header_size) / entry_size || u(header.value().bytes, 12, 4) != 0)
                return Error{ErrorCode::malformed, "Minidump HandleOperationList header or entry extent is invalid"};
            if (count > max_operations)
                return Error{ErrorCode::resource_limit, "Minidump handle operation count exceeds 65536"};
            // Charge both the source table read and retained model before any
            // allocation; extension bytes remain inspectable by source extent.
            const auto table_size = header_size + count * entry_size;
            const auto retained_size = count * sizeof(MinidumpHandleOperation) + sizeof(MinidumpHandleOperationList);
            if (budget > max_metadata_bytes || table_size > max_metadata_bytes - budget ||
                retained_size > max_metadata_bytes - budget - table_size)
                return Error{ErrorCode::resource_limit, "Minidump handle operation metadata exceeds its byte budget"};
            budget += table_size + retained_size;
            auto records = read(*storage, operations->rva, static_cast<std::size_t>(table_size));
            if (!records) return records.error();
            MinidumpHandleOperationList list;
            list.header_file_offset = FileOffset{operations->rva};
            list.header_size = static_cast<std::uint32_t>(header_size);
            list.entry_size = static_cast<std::uint32_t>(entry_size);
            list.operations.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t index = 0; index < count; ++index) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump handle operation decoding canceled"};
                const auto at = static_cast<std::size_t>(header_size + index * entry_size);
                MinidumpHandleOperation row;
                row.handle = u(records.value().bytes, at, 8);
                row.process_id = static_cast<std::uint32_t>(u(records.value().bytes, at + 8, 4));
                row.thread_id = static_cast<std::uint32_t>(u(records.value().bytes, at + 12, 4));
                row.operation_type = static_cast<std::uint32_t>(u(records.value().bytes, at + 16, 4));
                row.spare = static_cast<std::uint32_t>(u(records.value().bytes, at + 20, 4));
                row.backtrace_depth = static_cast<std::uint32_t>(u(records.value().bytes, at + 24, 4));
                row.backtrace_index = static_cast<std::uint32_t>(u(records.value().bytes, at + 28, 4));
                if (row.backtrace_depth > row.return_addresses.size())
                    return Error{ErrorCode::malformed, "Minidump handle operation backtrace depth exceeds 32"};
                for (std::size_t frame = 0; frame < row.return_addresses.size(); ++frame)
                    row.return_addresses[frame] = u(records.value().bytes, at + 32 + frame * 8, 8);
                row.record_file_offset = FileOffset{std::uint64_t{operations->rva} + at};
                row.return_addresses_file_offset = FileOffset{row.record_file_offset.value + 32};
                row.record_size = list.entry_size;
                list.operations.push_back(std::move(row));
            }
            metadata.handle_operations = std::move(list);
        }

        if (auto tokens = stream(stream_token_info)) {
            constexpr std::uint64_t header_min = 16, element_min = 16;
            constexpr std::uint64_t max_header = 4096, max_element_header = 4096, max_tokens = 65536;
            if (tokens->size < header_min)
                return Error{ErrorCode::malformed, "Minidump TokenInfoList header is truncated"};
            auto header = read(*storage, tokens->rva, header_min);
            if (!header) return header.error();
            const auto list_size = u(header.value().bytes, 0, 4);
            const auto count = u(header.value().bytes, 4, 4);
            const auto header_size = u(header.value().bytes, 8, 4);
            const auto element_header_size = u(header.value().bytes, 12, 4);
            if (list_size < header_min || list_size > tokens->size ||
                header_size < header_min || header_size > max_header || header_size > list_size ||
                element_header_size < element_min || element_header_size > max_element_header)
                return Error{ErrorCode::malformed, "Minidump TokenInfoList header or declared extent is invalid"};
            if (count > max_tokens)
                return Error{ErrorCode::resource_limit, "Minidump token count exceeds 65536"};
            const auto retained_size = count * sizeof(MinidumpTokenInfo) + sizeof(MinidumpTokenInfoList);
            if (budget > max_metadata_bytes || list_size > max_metadata_bytes - budget ||
                retained_size > max_metadata_bytes - budget - list_size)
                return Error{ErrorCode::resource_limit, "Minidump token metadata exceeds its byte budget"};
            budget += list_size + retained_size;
            auto list_bytes = read(*storage, tokens->rva, static_cast<std::size_t>(list_size));
            if (!list_bytes) return list_bytes.error();
            MinidumpTokenInfoList list;
            list.header_file_offset = FileOffset{tokens->rva};
            list.stream_size = static_cast<std::uint32_t>(list_size);
            list.list_header_size = static_cast<std::uint32_t>(header_size);
            list.element_header_size = static_cast<std::uint32_t>(element_header_size);
            list.tokens.reserve(static_cast<std::size_t>(count));
            std::uint64_t cursor = header_size;
            for (std::uint64_t index = 0; index < count; ++index) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump token metadata decoding canceled"};
                if (!extent(cursor, element_header_size, list_size))
                    return Error{ErrorCode::malformed, "Minidump token element header exceeds the declared list"};
                const auto at = static_cast<std::size_t>(cursor);
                const auto record_size = u(list_bytes.value().bytes, at, 4);
                if (record_size < element_header_size || !extent(cursor, record_size, list_size))
                    return Error{ErrorCode::malformed, "Minidump token record size exceeds the declared list"};
                MinidumpTokenInfo row;
                row.token_size = static_cast<std::uint32_t>(record_size);
                row.token_id = static_cast<std::uint32_t>(u(list_bytes.value().bytes, at + 4, 4));
                row.token_handle = u(list_bytes.value().bytes, at + 8, 8);
                row.record_file_offset = FileOffset{std::uint64_t{tokens->rva} + cursor};
                row.payload_file_offset = FileOffset{row.record_file_offset.value + element_header_size};
                row.payload_size = static_cast<std::uint32_t>(record_size - element_header_size);
                list.tokens.push_back(row);
                cursor += record_size;
            }
            if (cursor != list_size)
                return Error{ErrorCode::malformed, "Minidump token records do not consume the declared list extent"};
            metadata.token_info = std::move(list);
        }

        if (context_issue_count)
            metadata.diagnostics.emplace_back(std::to_string(context_issue_count) + " Minidump context records are partial, malformed, unsupported or have no captured groups");
        if (regions.empty()) metadata.diagnostics.emplace_back("Minidump contains no mapped memory-list regions");
        std::sort(regions.begin(), regions.end(), [](const auto &a, const auto &b) { return a.begin < b.begin; });
        for (std::size_t i = 1; i < regions.size(); ++i)
            if (regions[i].begin < regions[i - 1].begin + regions[i - 1].size)
                return Error{ErrorCode::malformed, "Minidump memory descriptors overlap"};

        Architecture arch = Architecture::unknown;
        ExecutionMode mode = ExecutionMode::unknown;
        std::uint8_t width = 64;
        switch (metadata.processor_architecture) {
        case 0: arch = Architecture::x86; mode = ExecutionMode::x86_32; width = 32; break;
        case 5: arch = Architecture::arm; width = 32; break;
        case 9: arch = Architecture::x86_64; mode = ExecutionMode::x86_64; break;
        case 12: arch = Architecture::arm64; mode = ExecutionMode::a64; break;
        case 0x8003: arch = Architecture::arm64; mode = ExecutionMode::a64; break;
        default:
            if (!regions.empty() && regions.back().begin + regions.back().size <= (UINT64_C(1) << 32)) width = 32;
            metadata.diagnostics.emplace_back("Minidump processor architecture is not supported for instruction decoding");
            break;
        }
        ImageLayout layout{{{0}, width, 1, ByteOrder::little}, arch, mode, {}, {}};
        LoadedImage loaded;
        loaded.metadata.format = "minidump";
        if (!regions.empty()) {
            loaded.metadata.preferred_base = regions.front().begin;
            const auto last_end = regions.back().begin + regions.back().size;
            loaded.metadata.image_size = last_end - regions.front().begin;
        }
        switch (metadata.processor_architecture) {
        case 0: loaded.metadata.machine = 0x014c; break;
        case 5: loaded.metadata.machine = 0x01c0; break;
        case 9: loaded.metadata.machine = 0x8664; break;
        case 12: loaded.metadata.machine = 0xaa64; break;
        case 0x8003: loaded.metadata.machine = 0xaa64; break;
        default: break;
        }
        loaded.metadata.minidump = std::move(metadata);
        loaded.metadata_complete = loaded.metadata.minidump->diagnostics.empty();
        auto &minidump = *loaded.metadata.minidump;
        if (protections.empty() && !regions.empty()) {
            minidump.diagnostics.emplace_back("Minidump has no MemoryInfoList; mapped bytes use provisional RWX permissions");
            loaded.metadata_complete = false;
        }
        bool protection_gap = false;
        auto append = [&](std::uint64_t begin, std::uint64_t size, std::uint64_t file,
                                std::uint32_t protect, std::uint32_t state, std::uint32_t type,
                                bool permission_known, std::optional<std::uint64_t> allocation_base = {},
                                std::optional<std::uint32_t> allocation_protect = {}) {
            if (!size) return;
            if (!permission_known) protection_gap = true;
            bool read_access = true, write_access = false, execute = !permission_known;
            if (permission_known) {
                const auto access = protect & 0xff;
                const bool committed = state == 0x1000; // MEM_COMMIT
                read_access = committed && (access == 0x02 || access == 0x04 || access == 0x08 ||
                                             access == 0x20 || access == 0x40 || access == 0x80);
                write_access = committed && (access == 0x04 || access == 0x08 || access == 0x40 || access == 0x80);
                execute = committed && (access == 0x10 || access == 0x20 || access == 0x40 || access == 0x80);
                if (access == 0x01 || (protect & 0x100)) read_access = write_access = execute = false;
            } else write_access = true;
            const auto index = minidump.memory.size();
            layout.segments.push_back({"memory" + std::to_string(index), {{0}, begin}, size, {file}, size,
                                       read_access, write_access, execute});
            minidump.memory.push_back({{{0}, begin}, size, {file}, protect, state, type,
                                       read_access, write_access, execute, allocation_base, allocation_protect});
            budget += sizeof(Segment) + sizeof(MinidumpMemoryRegion) + 24;
        };
        for (const auto &region : regions) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump loading canceled"};
            const auto end = region.begin + region.size;
            if (width < 64 && end > (UINT64_C(1) << width))
                return Error{ErrorCode::overflow, "Minidump address exceeds the declared processor width"};
            if (protections.empty()) {
                append(region.begin, region.size, region.file, 0, 0, 0, false);
                continue;
            }
            std::uint64_t cursor = region.begin;
            auto protection = std::lower_bound(protections.begin(), protections.end(), cursor,
                [](const auto &row, std::uint64_t value) { return row.end <= value; });
            for (; protection != protections.end() && protection->begin < end; ++protection) {
                if (protection->begin > cursor)
                    append(cursor, protection->begin - cursor, region.file + (cursor - region.begin), 0, 0, 0, false);
                const auto piece_begin = std::max(cursor, protection->begin);
                const auto piece_end = std::min(end, protection->end);
                if (piece_end > piece_begin)
                    append(piece_begin, piece_end - piece_begin, region.file + (piece_begin - region.begin),
                           protection->protect, protection->state, protection->type, true,
                           protection->allocation_base, protection->allocation_protect);
                cursor = std::max(cursor, piece_end);
                if (cursor >= end) break;
            }
            if (cursor < end)
                append(cursor, end - cursor, region.file + (cursor - region.begin), 0, 0, 0, false);
        }
        if (protection_gap && !protections.empty()) {
            minidump.diagnostics.emplace_back("Some captured memory ranges have no MemoryInfoList protection record; permissions are provisional");
            loaded.metadata_complete = false;
        }
        if (budget > max_metadata_bytes)
            return Error{ErrorCode::resource_limit, "Minidump metadata exceeds its byte budget"};
        if (minidump.exception) {
            const Address at{{0}, minidump.exception->address};
            if (std::any_of(layout.segments.begin(), layout.segments.end(), [&](const auto &segment) {
                    return at.offset >= segment.begin.offset && at.offset - segment.begin.offset < segment.size;
                })) layout.entries.push_back(at);
        }
        auto image = Image::create(storage, std::move(layout));
        if (!image) return image.error();
        loaded.image = std::move(image.value());
        loaded.metadata_reads = tracking.value()->reads();
        loaded.metadata_reads_complete = true;
        if (minidump.streams.empty())
            return Error{ErrorCode::malformed, "Minidump has no stream directory entries"};
        if (!minidump.diagnostics.empty()) {
            for (const auto &message : minidump.diagnostics)
                loaded.diagnostics.push_back({DiagnosticSeverity::warning, message, {}});
            loaded.metadata_complete = false;
        }
        return loaded;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate Minidump metadata"};
    } catch (...) {
        return Error{ErrorCode::malformed, "Minidump parsing failed"};
    }
}
} // namespace hexlab
