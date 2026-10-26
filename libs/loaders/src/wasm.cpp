#include "hexlab/loaders/wasm.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>

namespace hexlab {
namespace {
constexpr std::uint64_t max_input_bytes = 256u * 1024u * 1024u;
constexpr std::uint32_t max_vector_items = 1'000'000;
constexpr std::size_t max_wasm_control_depth = 100'000;
constexpr std::size_t max_wasm_operand_stack = 1'000'000;
constexpr std::uint32_t max_wasm_multi_values = 128;
constexpr std::uint32_t max_name_bytes = 1024u * 1024u;
constexpr std::uint64_t max_total_name_bytes = 16u * 1024u * 1024u;
constexpr std::uint64_t wasm_page_bytes = 65536;
constexpr std::uint32_t wasm_memory_space_id = max_vector_items;
struct Reader {
    std::span<const std::byte> bytes;
    std::size_t position = 0;
    bool byte(std::uint8_t &value) {
        if (position >= bytes.size()) return false;
        value = std::to_integer<std::uint8_t>(bytes[position++]);
        return true;
    }
    bool uleb(std::uint32_t &value) {
        value = 0;
        for (unsigned i = 0; i < 5; ++i) {
            std::uint8_t b = 0;
            if (!byte(b)) return false;
            if (i == 4 && (b & 0xf0)) return false;
            value |= std::uint32_t(b & 0x7f) << (7 * i);
            if (!(b & 0x80)) return true;
        }
        return false;
    }
    bool skip(std::size_t count) {
        if (count > bytes.size() - position) return false;
        position += count;
        return true;
    }
    bool name() {
        std::uint32_t count = 0;
        if (!uleb(count) || count > bytes.size() - position) return false;
        position += count;
        return true;
    }
    bool name(std::string &value, std::uint64_t &name_bytes) {
        std::uint32_t count = 0;
        if (!uleb(count) || count > max_name_bytes || count > bytes.size() - position ||
            count > max_total_name_bytes - std::min(name_bytes, max_total_name_bytes))
            return false;
        const auto *begin = reinterpret_cast<const char *>(bytes.data() + position);
        value.assign(begin, count);
        const auto *data = reinterpret_cast<const unsigned char *>(value.data());
        for (std::size_t i = 0; i < value.size();) {
            const auto first = data[i];
            if (first <= 0x7f) { ++i; continue; }
            unsigned continuation = first >= 0xc2 && first <= 0xdf ? 1
                                   : first >= 0xe0 && first <= 0xef ? 2
                                   : first >= 0xf0 && first <= 0xf4 ? 3 : 99;
            if (continuation == 99 || i + continuation >= value.size()) return false;
            for (unsigned n = 1; n <= continuation; ++n)
                if ((data[i + n] & 0xc0) != 0x80) return false;
            if ((first == 0xe0 && data[i + 1] < 0xa0) || (first == 0xed && data[i + 1] >= 0xa0) ||
                (first == 0xf0 && data[i + 1] < 0x90) || (first == 0xf4 && data[i + 1] >= 0x90))
                return false;
            i += continuation + 1;
        }
        position += count;
        name_bytes += count;
        return true;
    }
    bool value_type(std::uint8_t *decoded = nullptr) {
        std::uint8_t type = 0;
        if (!byte(type)) return false;
        if (type != 0x7f && type != 0x7e && type != 0x7d && type != 0x7c) return false;
        if (decoded) *decoded = type;
        return true;
    }
    bool sleb(unsigned bits, std::int64_t &value) {
        const unsigned limit = (bits + 6) / 7;
        std::uint64_t raw = 0;
        unsigned shift = 0;
        std::uint8_t b = 0;
        for (unsigned i = 0; i < limit; ++i) {
            if (!byte(b)) return false;
            const auto payload = static_cast<std::uint64_t>(b & 0x7f);
            const auto remaining = bits - i * 7;
            if (remaining < 7) {
                const bool negative = (payload & (std::uint64_t{1} << (remaining - 1))) != 0;
                const auto unused = payload >> remaining;
                const auto expected = negative ? ((std::uint64_t{1} << (7 - remaining)) - 1) : 0;
                if (unused != expected) return false;
            }
            if (shift < 64) raw |= payload << shift;
            shift += 7;
            if (!(b & 0x80)) {
                if (shift < 64 && (b & 0x40)) raw |= (~std::uint64_t{0}) << shift;
                if (bits < 64) {
                    const auto mask = (std::uint64_t{1} << bits) - 1;
                    raw &= mask;
                    if (raw & (std::uint64_t{1} << (bits - 1))) raw |= ~mask;
                }
                value = static_cast<std::int64_t>(raw);
                return true;
            }
        }
        return false;
    }
    bool limits(bool memory, WasmLimits &result) {
        std::uint32_t flags = 0, minimum = 0, maximum = 0;
        if (!uleb(flags) || (flags & ~(memory ? std::uint32_t{0x3} : std::uint32_t{0x1})) || !uleb(minimum)) return false;
        if (memory && minimum > 65536) return false; // wasm32 is at most 4 GiB (65,536 pages).
        if ((flags & 0x2) && !(flags & 0x1)) return false; // shared memory requires a maximum
        if ((flags & 0x1) && (!uleb(maximum) || maximum < minimum || (memory && maximum > 65536))) return false;
        result.minimum = minimum;
        if (flags & 1) result.maximum = maximum;
        result.shared = (flags & 2) != 0;
        return true;
    }
    bool sleb(unsigned bits) {
        const unsigned max_bytes = (bits + 6) / 7;
        for (unsigned i = 0; i < max_bytes; ++i) {
            std::uint8_t b = 0;
            if (!byte(b)) return false;
            if (!(b & 0x80)) {
                if (i + 1 == max_bytes && bits % 7) {
                    const unsigned used = bits % 7;
                    const auto payload = static_cast<unsigned>(b & 0x7f);
                    const auto value_mask = (1u << used) - 1;
                    const auto unused_mask = 0x7fu ^ value_mask;
                    const bool negative = (payload & (1u << (used - 1))) != 0;
                    if ((negative && (payload & unused_mask) != unused_mask) ||
                        (!negative && (payload & unused_mask) != 0)) return false;
                }
                return true;
            }
        }
        return false;
    }
};
struct FunctionBody {
    std::uint32_t index = 0;
    std::uint64_t code_offset = 0, code_size = 0;
    std::uint32_t local_count = 0;
    std::vector<std::pair<std::uint32_t, std::uint8_t>> local_groups;
};
struct GlobalType { std::uint8_t value = 0; bool mutable_value = false; };
int section_order(std::uint8_t id) {
    if (id >= 1 && id <= 9) return id;
    if (id == 12) return 10; // data-count precedes code in the binary encoding
    if (id == 10) return 11;
    if (id == 11) return 12;
    return -1;
}
const char *unparsed_section_name(std::uint8_t id) {
    switch (id) {
    case 8: return "start";
    case 9: return "element";
    case 11: return "data";
    case 12: return "data-count";
    default: return "unknown";
    }
}
bool parse_types(Reader &r, std::uint32_t &type_count, WasmMetadata &metadata,
                 std::string &reason, bool &unsupported) {
    if (!r.uleb(type_count) || type_count > max_vector_items) return false;
    metadata.function_types.reserve(type_count);
    for (std::uint32_t i = 0; i < type_count; ++i) {
        std::uint8_t form = 0;
        std::uint32_t count = 0;
        if (!r.byte(form) || form != 0x60 || !r.uleb(count) || count > max_vector_items) return false;
        const auto parameter_count = count;
        std::vector<std::uint8_t> parameter_types;
        parameter_types.reserve(parameter_count);
        for (std::uint32_t p = 0; p < count; ++p) {
            std::uint8_t type = 0;
            if (!r.value_type(&type)) return false;
            parameter_types.push_back(type);
        }
        if (!r.uleb(count)) return false;
        if (count > max_wasm_multi_values) {
            unsupported = true;
            reason = "function result vector exceeds the 128-value multi-value limit";
            return false;
        }
        std::vector<std::uint8_t> result_types;
        result_types.reserve(count);
        for (std::uint32_t p = 0; p < count; ++p) {
            std::uint8_t type = 0;
            if (!r.value_type(&type)) return false;
            result_types.push_back(type);
        }
        metadata.function_types.push_back({parameter_count, count, std::move(parameter_types), std::move(result_types)});
    }
    return r.position == r.bytes.size();
}
bool parse_imports(Reader &r, std::uint32_t type_count, WasmMetadata &metadata,
                   std::uint64_t section_file_offset, std::uint64_t &name_bytes,
                   std::string &reason, bool &unsupported) {
    std::uint32_t count = 0;
    if (!r.uleb(count) || count > max_vector_items) { reason = "invalid import vector count"; return false; }
    metadata.imports.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint8_t kind = 0;
        WasmImport entry;
        entry.entry_index = i;
        entry.section_file_offset = {section_file_offset};
        entry.entry_file_offset = {section_file_offset + r.position};
        if (!r.name(entry.module, name_bytes) || !r.name(entry.name, name_bytes) || !r.byte(kind)) {
            reason = "invalid import name or truncated import descriptor"; return false;
        }
        if (kind > static_cast<std::uint8_t>(WasmExternalKind::global)) {
            unsupported = true; reason = "unsupported WebAssembly import kind " + std::to_string(kind); return false;
        }
        entry.kind = static_cast<WasmExternalKind>(kind);
        if (kind == 0) {
            std::uint32_t type = 0;
            if (!r.uleb(type) || type >= type_count) { reason = "function import has an invalid type index"; return false; }
            entry.index = metadata.imported_functions++;
            entry.function_type_index = type;
            metadata.function_type_indices.push_back(type);
        } else if (kind == 1) {
            std::uint8_t element = 0;
            if (!r.byte(element)) { reason = "truncated table import type"; return false; }
            if (element != 0x70) { unsupported = true; reason = "unsupported WebAssembly table reference type"; return false; }
            WasmLimits limits;
            if (!r.limits(false, limits)) { reason = "invalid table import limits"; return false; }
            entry.index = metadata.imported_tables++;
            entry.limits = limits;
        } else if (kind == 2) {
            WasmLimits limits;
            if (!r.limits(true, limits)) { reason = "invalid memory import limits"; return false; }
            entry.index = metadata.imported_memories++;
            entry.limits = limits;
        } else if (kind == 3) {
            std::uint8_t mutability = 0;
            if (!r.value_type() || !r.byte(mutability) || mutability > 1) { reason = "invalid global import type"; return false; }
            entry.index = metadata.imported_globals++;
            entry.global_value_type = std::to_integer<std::uint8_t>(r.bytes[r.position - 2]);
            entry.global_mutable = mutability != 0;
        }
        if (metadata.imports.size() >= max_vector_items) { reason = "import metadata budget exceeded"; return false; }
        metadata.imports.push_back(std::move(entry));
    }
    if (r.position != r.bytes.size()) { reason = "trailing bytes in import section"; return false; }
    return true;
}
bool parse_functions(Reader &r, std::uint32_t type_count, std::vector<std::uint32_t> &function_types) {
    std::uint32_t count = 0;
    if (!r.uleb(count) || count > max_vector_items) return false;
    function_types.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint32_t type = 0;
        if (!r.uleb(type) || type >= type_count) return false;
        function_types.push_back(type);
    }
    return r.position == r.bytes.size();
}
bool parse_exports(Reader &r, WasmMetadata &metadata, std::uint64_t section_file_offset,
                   std::uint64_t &name_bytes, std::string &reason, bool &unsupported) {
    std::uint32_t count = 0;
    if (!r.uleb(count) || count > max_vector_items) { reason = "invalid export vector count"; return false; }
    metadata.exports.reserve(count);
    std::set<std::string> names;
    for (std::uint32_t i = 0; i < count; ++i) {
        WasmExport entry;
        std::uint8_t kind = 0;
        entry.entry_index = i;
        entry.section_file_offset = {section_file_offset};
        entry.entry_file_offset = {section_file_offset + r.position};
        if (!r.name(entry.name, name_bytes) || !r.byte(kind) || !r.uleb(entry.index)) {
            reason = "invalid export name or truncated export descriptor"; return false;
        }
        if (kind > static_cast<std::uint8_t>(WasmExternalKind::global)) {
            unsupported = true; reason = "unsupported WebAssembly export kind " + std::to_string(kind); return false;
        }
        if (!names.insert(entry.name).second) { reason = "duplicate WebAssembly export name"; return false; }
        entry.kind = static_cast<WasmExternalKind>(kind);
        metadata.exports.push_back(std::move(entry));
    }
    if (r.position != r.bytes.size()) { reason = "trailing bytes in export section"; return false; }
    return true;
}

bool parse_name_section(Reader &section, std::uint64_t section_file_offset, WasmMetadata &metadata,
                        std::uint64_t &name_bytes, std::string &reason) {
    std::set<std::uint32_t> function_indices;
    std::set<std::pair<std::uint32_t, std::uint32_t>> local_indices;
    while (section.position < section.bytes.size()) {
        std::uint8_t subsection_id = 0;
        std::uint32_t subsection_size = 0;
        if (!section.byte(subsection_id) || !section.uleb(subsection_size) ||
            subsection_size > section.bytes.size() - section.position) {
            reason = "invalid WebAssembly name subsection header or extent";
            return false;
        }
        Reader subsection{section.bytes.subspan(section.position, subsection_size)};
        const auto subsection_offset = section_file_offset + section.position;
        if (subsection_id == 1) {
            std::uint32_t count = 0;
            if (!subsection.uleb(count) || count > max_vector_items ||
                count > max_vector_items - metadata.function_names.size()) {
                reason = "invalid WebAssembly function-name map count";
                return false;
            }
            for (std::uint32_t i = 0; i < count; ++i) {
                WasmFunctionName item;
                item.entry_file_offset = {subsection_offset + subsection.position};
                if (!subsection.uleb(item.function_index) || !subsection.name(item.name, name_bytes)) {
                    reason = "invalid WebAssembly function-name entry";
                    return false;
                }
                if (!function_indices.insert(item.function_index).second) {
                    reason = "duplicate WebAssembly function-name index";
                    return false;
                }
                metadata.function_names.push_back(std::move(item));
            }
            if (subsection.position != subsection.bytes.size()) {
                reason = "trailing bytes in WebAssembly function-name subsection";
                return false;
            }
        } else if (subsection_id == 2) {
            std::uint32_t function_count = 0;
            if (!subsection.uleb(function_count) || function_count > max_vector_items) {
                reason = "invalid WebAssembly local-name function count";
                return false;
            }
            for (std::uint32_t i = 0; i < function_count; ++i) {
                std::uint32_t function_index = 0, local_count = 0;
                if (!subsection.uleb(function_index) || !subsection.uleb(local_count) ||
                    local_count > max_vector_items || local_count > max_vector_items - metadata.local_names.size()) {
                    reason = "invalid WebAssembly local-name map";
                    return false;
                }
                for (std::uint32_t n = 0; n < local_count; ++n) {
                    WasmLocalName item;
                    item.function_index = function_index;
                    item.entry_file_offset = {subsection_offset + subsection.position};
                    if (!subsection.uleb(item.local_index) || !subsection.name(item.name, name_bytes)) {
                        reason = "invalid WebAssembly local-name entry";
                        return false;
                    }
                    if (!local_indices.insert({item.function_index, item.local_index}).second) {
                        reason = "duplicate WebAssembly local-name index";
                        return false;
                    }
                    metadata.local_names.push_back(std::move(item));
                }
            }
            if (subsection.position != subsection.bytes.size()) {
                reason = "trailing bytes in WebAssembly local-name subsection";
                return false;
            }
        }
        // Unknown name subsections are optional debug metadata. Their enclosing
        // length still gives an exact bounded skip while preserving the source.
        section.position += subsection_size;
    }
    return true;
}

bool parse_start(Reader &r, WasmMetadata &metadata, std::uint64_t section_file_offset,
                 std::string &reason) {
    WasmStartFunction start;
    start.section_file_offset = {section_file_offset};
    start.entry_file_offset = {section_file_offset + r.position};
    if (!r.uleb(start.function_index)) {
        reason = "invalid start function index";
        return false;
    }
    if (r.position != r.bytes.size()) {
        reason = "trailing bytes in start section";
        return false;
    }
    metadata.start_function = start;
    return true;
}

bool read_i32_constant(Reader &r, std::uint32_t &value) {
    std::uint64_t bits = 0;
    unsigned shift = 0;
    for (unsigned i = 0; i < 5; ++i) {
        std::uint8_t byte = 0;
        if (!r.byte(byte)) return false;
        bits |= std::uint64_t(byte & 0x7f) << shift;
        shift += 7;
        if (!(byte & 0x80)) {
            if (i == 4) {
                const auto high = byte & 0x70;
                if (high != 0 && high != 0x70) return false;
            }
            const auto signed_value = (byte & 0x40) && shift < 64
                ? static_cast<std::int64_t>(bits | (~std::uint64_t{0} << shift))
                : static_cast<std::int64_t>(bits);
            if (signed_value < std::numeric_limits<std::int32_t>::min() ||
                signed_value > std::numeric_limits<std::int32_t>::max()) return false;
            value = static_cast<std::uint32_t>(signed_value);
            return true;
        }
    }
    return false;
}

bool parse_data_count(Reader &r, WasmMetadata &metadata, std::string &reason) {
    std::uint32_t count = 0;
    if (!r.uleb(count) || count > max_vector_items || r.position != r.bytes.size()) {
        reason = "invalid WebAssembly data-count section";
        return false;
    }
    metadata.declared_data_count = count;
    return true;
}

bool parse_data(Reader &r, WasmMetadata &metadata, std::uint64_t section_file_offset,
                std::string &reason, bool &unsupported) {
    std::uint32_t count = 0;
    if (!r.uleb(count) || count > max_vector_items) {
        reason = "invalid WebAssembly data segment count";
        return false;
    }
    metadata.data_segments.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        WasmDataSegment segment;
        segment.section_file_offset = {section_file_offset};
        segment.entry_file_offset = {section_file_offset + r.position};
        std::uint32_t flags = 0;
        if (!r.uleb(flags) || flags > 2) {
            unsupported = flags > 2;
            reason = "unsupported or malformed WebAssembly data segment mode";
            return false;
        }
        if (flags == 1) {
            segment.mode = WasmDataMode::passive;
        } else {
            segment.mode = WasmDataMode::active;
            if (flags == 2 && !r.uleb(segment.memory_index)) {
                reason = "truncated WebAssembly data segment memory index";
                return false;
            }
            std::uint8_t opcode = 0;
            if (!r.byte(opcode)) {
                reason = "truncated WebAssembly data segment offset expression";
                return false;
            }
            if (opcode == 0x41) {
                segment.offset_kind = WasmOffsetExpressionKind::i32_constant;
                if (!read_i32_constant(r, segment.offset_value)) {
                    reason = "invalid i32.const WebAssembly data segment offset";
                    return false;
                }
            } else if (opcode == 0x23) {
                segment.offset_kind = WasmOffsetExpressionKind::global_get;
                if (!r.uleb(segment.offset_value)) {
                    reason = "invalid global.get WebAssembly data segment offset";
                    return false;
                }
            } else {
                unsupported = true;
                reason = "unsupported WebAssembly data segment offset expression";
                return false;
            }
            std::uint8_t end = 0;
            if (!r.byte(end) || end != 0x0b) {
                reason = "WebAssembly data segment offset expression has no end opcode";
                return false;
            }
        }
        std::uint32_t size = 0;
        if (!r.uleb(size) || size > r.bytes.size() - r.position) {
            reason = "truncated WebAssembly data segment bytes";
            return false;
        }
        segment.byte_count = size;
        segment.bytes_file_offset = {section_file_offset + r.position};
        if (!r.skip(size)) {
            reason = "truncated WebAssembly data segment bytes";
            return false;
        }
        metadata.data_segments.push_back(segment);
    }
    if (r.position != r.bytes.size()) {
        reason = "trailing bytes in WebAssembly data section";
        return false;
    }
    return true;
}

bool parse_tables(Reader &r, std::uint32_t &count, WasmMetadata &metadata,
                  std::string &reason, bool &unsupported) {
    if (!r.uleb(count) || count > max_vector_items) { reason = "invalid table vector count"; return false; }
    metadata.defined_table_limits.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint8_t element = 0;
        WasmLimits limits;
        if (!r.byte(element)) { reason = "truncated table type"; return false; }
        if (element != 0x70) { unsupported = true; reason = "unsupported WebAssembly table reference type"; return false; }
        if (!r.limits(false, limits)) { reason = "invalid table limits"; return false; }
        metadata.defined_table_limits.push_back(limits);
    }
    if (r.position != r.bytes.size()) { reason = "trailing bytes in table section"; return false; }
    return true;
}

bool parse_elements(Reader &r, WasmMetadata &metadata, std::uint64_t section_file_offset,
                    std::string &reason, bool &unsupported) {
    std::uint32_t count = 0;
    if (!r.uleb(count) || count > max_vector_items) {
        reason = "invalid WebAssembly element segment count";
        return false;
    }
    metadata.element_segments.reserve(count);
    std::uint64_t total_functions = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        WasmElementSegment segment;
        segment.section_file_offset = {section_file_offset};
        segment.entry_file_offset = {section_file_offset + r.position};
        std::uint32_t flags = 0;
        if (!r.uleb(flags)) { reason = "truncated WebAssembly element segment flags"; return false; }
        if (flags > 3) {
            unsupported = true;
            reason = "unsupported WebAssembly element segment encoding";
            return false;
        }
        if (flags == 1) segment.mode = WasmElementMode::passive;
        else if (flags == 3) segment.mode = WasmElementMode::declarative;
        else {
            segment.mode = WasmElementMode::active;
            if (flags == 2 && !r.uleb(segment.table_index)) {
                reason = "truncated WebAssembly element segment table index";
                return false;
            }
            std::uint8_t opcode = 0;
            if (!r.byte(opcode)) { reason = "truncated WebAssembly element offset expression"; return false; }
            if (opcode == 0x41) {
                segment.offset_kind = WasmOffsetExpressionKind::i32_constant;
                if (!read_i32_constant(r, segment.offset_value)) {
                    reason = "invalid i32.const WebAssembly element offset";
                    return false;
                }
            } else if (opcode == 0x23) {
                segment.offset_kind = WasmOffsetExpressionKind::global_get;
                if (!r.uleb(segment.offset_value)) {
                    reason = "invalid global.get WebAssembly element offset";
                    return false;
                }
            } else {
                unsupported = true;
                reason = "unsupported WebAssembly element offset expression";
                return false;
            }
            std::uint8_t end = 0;
            if (!r.byte(end) || end != 0x0b) {
                reason = "WebAssembly element offset expression has no end opcode";
                return false;
            }
        }
        if (flags != 0) {
            std::uint8_t element_kind = 0;
            if (!r.byte(element_kind) || element_kind != 0) {
                unsupported = element_kind != 0;
                reason = "unsupported or malformed WebAssembly element kind";
                return false;
            }
        }
        std::uint32_t function_count = 0;
        if (!r.uleb(function_count) || function_count > max_vector_items ||
            total_functions + function_count > max_vector_items) {
            reason = "invalid WebAssembly element function vector count";
            return false;
        }
        total_functions += function_count;
        segment.function_indices.reserve(function_count);
        for (std::uint32_t n = 0; n < function_count; ++n) {
            std::uint32_t function_index = 0;
            if (!r.uleb(function_index)) {
                reason = "truncated WebAssembly element function index";
                return false;
            }
            segment.function_indices.push_back(function_index);
        }
        metadata.element_segments.push_back(std::move(segment));
    }
    if (r.position != r.bytes.size()) {
        reason = "trailing bytes in WebAssembly element section";
        return false;
    }
    return true;
}

Result<bool> apply_initial_table_elements(WasmMetadata &metadata,
                                          std::vector<Diagnostic> &diagnostics) {
    const auto table_count = static_cast<std::uint64_t>(metadata.imported_tables) + metadata.defined_tables;
    const bool imported = metadata.imported_tables != 0;
    const WasmLimits *limits = nullptr;
    if (imported) {
        const auto table = std::find_if(metadata.imports.begin(), metadata.imports.end(), [](const WasmImport &item) {
            return item.kind == WasmExternalKind::table && item.index == 0;
        });
        if (table != metadata.imports.end() && table->limits) limits = &*table->limits;
    } else if (!metadata.defined_table_limits.empty()) {
        limits = &metadata.defined_table_limits.front();
    }
    if (table_count && !limits)
        return Error{ErrorCode::malformed, "WebAssembly table limits are unavailable after parsing"};
    metadata.initial_table_element_count = limits ? limits->minimum : 0;
    metadata.initial_table_complete = table_count != 0 && !imported;

    bool unresolved_offset = false;
    bool out_of_bounds = false;
    std::map<std::uint32_t, std::uint32_t> slots;
    for (const auto &segment : metadata.element_segments) {
        for (const auto function_index : segment.function_indices) {
            if (function_index >= metadata.function_type_indices.size())
                return Error{ErrorCode::malformed, "WebAssembly element function index is outside the function index space"};
        }
        if (segment.mode != WasmElementMode::active) continue;
        if (segment.table_index >= table_count)
            return Error{ErrorCode::malformed, "WebAssembly active element segment references a missing table"};
        if (segment.offset_kind != WasmOffsetExpressionKind::i32_constant) {
            unresolved_offset = true;
            continue;
        }
        const auto end = checked_add(segment.offset_value, segment.function_indices.size());
        if (!end || end.value() > metadata.initial_table_element_count) {
            out_of_bounds = true;
            continue;
        }
        for (std::size_t i = 0; i < segment.function_indices.size(); ++i)
            slots[segment.offset_value + static_cast<std::uint32_t>(i)] = segment.function_indices[i];
    }
    if (unresolved_offset || out_of_bounds) {
        metadata.initial_table_complete = false;
        if (unresolved_offset)
            diagnostics.push_back({DiagnosticSeverity::warning,
                "WebAssembly initial table view omitted because an active element segment uses an unresolved global.get offset", {}});
        if (out_of_bounds)
            diagnostics.push_back({DiagnosticSeverity::warning,
                "WebAssembly initial table view omitted because an active element segment exceeds the initial table extent", {}});
        return true;
    }
    metadata.initial_table_elements.reserve(slots.size());
    for (const auto &[slot, function_index] : slots)
        metadata.initial_table_elements.push_back({slot, function_index});
    return true;
}

bool parse_memories(Reader &r, std::uint32_t &count, WasmMetadata &metadata,
                    std::string &reason, bool &unsupported) {
    if (!r.uleb(count) || count > max_vector_items) { reason = "invalid memory vector count"; return false; }
    metadata.defined_memory_limits.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        WasmLimits limits;
        if (!r.limits(true, limits)) { reason = "invalid memory limits"; return false; }
        metadata.defined_memory_limits.push_back(limits);
    }
    if (r.position != r.bytes.size()) { reason = "trailing bytes in memory section"; return false; }
    if (count > 1) {
        unsupported = true;
        reason = "multiple WebAssembly memories require a proposal not enabled by this loader";
        return false;
    }
    return true;
}

struct DataEvent {
    std::uint64_t offset = 0;
    std::size_t segment = 0;
    bool begins = false;
};

Result<bool> map_linear_memory(WasmMetadata &metadata, ImageLayout &layout,
                               std::vector<Diagnostic> &diagnostics, std::stop_token stop) {
    const auto memory_count = static_cast<std::uint64_t>(metadata.imported_memories) + metadata.defined_memories;
    if (memory_count == 0) return true;

    const bool imported = metadata.imported_memories != 0;
    const WasmLimits *limits = nullptr;
    if (imported) {
        const auto memory = std::find_if(metadata.imports.begin(), metadata.imports.end(), [](const WasmImport &item) {
            return item.kind == WasmExternalKind::memory && item.index == 0;
        });
        if (memory != metadata.imports.end() && memory->limits) limits = &*memory->limits;
    } else if (!metadata.defined_memory_limits.empty()) {
        limits = &metadata.defined_memory_limits.front();
    }
    if (!limits) return Error{ErrorCode::malformed, "WebAssembly memory limits are unavailable after parsing"};
    const auto memory_size = static_cast<std::uint64_t>(limits->minimum) * wasm_page_bytes;
    metadata.linear_memory_size = memory_size;

    std::vector<std::size_t> active_segments;
    active_segments.reserve(metadata.data_segments.size());
    for (std::size_t i = 0; i < metadata.data_segments.size(); ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly memory initialization canceled"};
        const auto &segment = metadata.data_segments[i];
        if (segment.mode != WasmDataMode::active) continue;
        if (segment.offset_kind != WasmOffsetExpressionKind::i32_constant) {
            diagnostics.push_back({DiagnosticSeverity::warning,
                "WebAssembly linear-memory view omitted because an active data segment uses an unresolved global.get offset", {}});
            return true;
        }
        const auto end = checked_add(segment.offset_value, segment.byte_count);
        if (!end || end.value() > memory_size) {
            diagnostics.push_back({DiagnosticSeverity::warning,
                "WebAssembly linear-memory view omitted because an active data segment exceeds the initial memory extent", {}});
            return true;
        }
        if (segment.byte_count != 0) active_segments.push_back(i);
    }

    // A defined memory starts zero-filled. An imported memory's untouched
    // bytes belong to the host and remain unmapped in this static image.
    if (imported && active_segments.empty()) return true;
    if (active_segments.size() > max_vector_items / 2) {
        diagnostics.push_back({DiagnosticSeverity::warning,
            "WebAssembly linear-memory view omitted because active data segments exceed the event budget", {}});
        return true;
    }

    std::vector<DataEvent> events;
    events.reserve(active_segments.size() * 2);
    for (const auto index : active_segments) {
        const auto &segment = metadata.data_segments[index];
        const auto end = static_cast<std::uint64_t>(segment.offset_value) + segment.byte_count;
        events.push_back({segment.offset_value, index, true});
        events.push_back({end, index, false});
    }
    std::sort(events.begin(), events.end(), [](const DataEvent &left, const DataEvent &right) {
        if (left.offset != right.offset) return left.offset < right.offset;
        return left.begins < right.begins;
    });
    std::vector<std::uint64_t> boundaries;
    boundaries.reserve(events.size() + (imported ? 0 : 2));
    if (!imported) {
        boundaries.push_back(0);
        boundaries.push_back(memory_size);
    }
    for (const auto &event : events) boundaries.push_back(event.offset);
    std::sort(boundaries.begin(), boundaries.end());
    boundaries.erase(std::unique(boundaries.begin(), boundaries.end()), boundaries.end());

    std::vector<Segment> memory_segments;
    std::set<std::size_t> active;
    std::size_t event_index = 0;
    for (std::size_t boundary_index = 0; boundary_index + 1 < boundaries.size(); ++boundary_index) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly memory mapping canceled"};
        const auto begin = boundaries[boundary_index];
        const auto end = boundaries[boundary_index + 1];
        while (event_index < events.size() && events[event_index].offset == begin && !events[event_index].begins) {
            active.erase(events[event_index].segment);
            ++event_index;
        }
        while (event_index < events.size() && events[event_index].offset == begin && events[event_index].begins) {
            active.insert(events[event_index].segment);
            ++event_index;
        }
        if (begin == end || (imported && active.empty())) continue;

        const bool initialized = !active.empty();
        const auto file_begin = initialized
            ? metadata.data_segments[*active.rbegin()].bytes_file_offset.value +
                  (begin - metadata.data_segments[*active.rbegin()].offset_value)
            : std::uint64_t{0};
        Segment mapped{initialized ? "wasm-linear-memory.data" : "wasm-linear-memory.zero",
                       {{wasm_memory_space_id}, begin}, end - begin, {file_begin},
                       initialized ? end - begin : 0, true, true, false};
        if (!memory_segments.empty()) {
            auto &previous = memory_segments.back();
            const auto previous_end = previous.begin.offset + previous.size;
            const bool same_backing = (previous.file_size == 0 && mapped.file_size == 0) ||
                (previous.file_size == previous.size && mapped.file_size == mapped.size &&
                 previous.file_begin.value + previous.file_size == mapped.file_begin.value);
            if (previous_end == begin && same_backing) {
                previous.size += mapped.size;
                previous.file_size += mapped.file_size;
                continue;
            }
        }
        if (memory_segments.size() >= max_vector_items) {
            diagnostics.push_back({DiagnosticSeverity::warning,
                "WebAssembly linear-memory view omitted because initialized ranges exceed the segment budget", {}});
            return true;
        }
        memory_segments.push_back(std::move(mapped));
    }

    const bool has_known_bytes = !memory_segments.empty();
    if (!imported || has_known_bytes) {
        const AddressSpace memory_space{{wasm_memory_space_id}, 32, 1, ByteOrder::little};
        layout.domains.push_back({memory_space, {Architecture::wasm, ExecutionMode::wasm32, ByteOrder::little}});
        layout.segments.insert(layout.segments.end(), memory_segments.begin(), memory_segments.end());
        metadata.linear_memory_space = memory_space.id;
        metadata.linear_memory_complete = !imported;
    }
    return true;
}

bool parse_globals(Reader &r, std::uint32_t &count, std::uint32_t imported_count,
                   std::vector<GlobalType> &globals,
                   WasmMetadata &metadata,
                   std::string &reason, bool &unsupported) {
    if (!r.uleb(count) || count > max_vector_items) { reason = "invalid global vector count"; return false; }
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint8_t mutability = 0;
        std::uint8_t type = 0;
        if (!r.value_type(&type) || !r.byte(mutability) || mutability > 1) { reason = "invalid global type"; return false; }
        std::uint8_t opcode = 0, end = 0;
        if (!r.byte(opcode)) { reason = "truncated global initializer"; return false; }
        if (opcode == 0x41 && type == 0x7f) {
            if (!r.sleb(32)) { reason = "invalid i32 global initializer"; return false; }
        } else if (opcode == 0x42 && type == 0x7e) {
            if (!r.sleb(64)) { reason = "invalid i64 global initializer"; return false; }
        } else if (opcode == 0x43 && type == 0x7d) {
            if (!r.skip(4)) { reason = "truncated f32 global initializer"; return false; }
        } else if (opcode == 0x44 && type == 0x7c) {
            if (!r.skip(8)) { reason = "truncated f64 global initializer"; return false; }
        } else if (opcode == 0x23) {
            std::uint32_t index = 0;
            if (!r.uleb(index) || index >= imported_count ||
                globals[index].mutable_value || globals[index].value != type) {
                reason = "global initializer must read an immutable imported global of matching type";
                return false;
            }
        } else if (opcode == 0x41 || opcode == 0x42 || opcode == 0x43 || opcode == 0x44) {
            reason = "global initializer type mismatch"; return false;
        } else {
            unsupported = true; reason = "unsupported WebAssembly global initializer opcode " + std::to_string(opcode); return false;
        }
        if (!r.byte(end) || end != 0x0b) { reason = "global initializer must contain one expression and end"; return false; }
        globals.push_back({type, mutability != 0});
        metadata.globals.push_back({type, mutability != 0, false});
    }
    if (r.position != r.bytes.size()) { reason = "trailing bytes in global section"; return false; }
    return true;
}
bool parse_code(Reader &r, std::uint32_t imported_count, std::vector<FunctionBody> &bodies,
                std::uint64_t section_file_offset) {
    std::uint32_t count = 0;
    if (!r.uleb(count) || count > max_vector_items) return false;
    bodies.reserve(count);
    std::uint64_t local_total = 0;
    for (std::uint32_t n = 0; n < count; ++n) {
        std::uint32_t body_size = 0;
        if (!r.uleb(body_size) || body_size > r.bytes.size() - r.position) return false;
        Reader body{r.bytes.subspan(r.position, body_size)};
        std::uint32_t groups = 0;
        if (!body.uleb(groups) || groups > max_vector_items) return false;
        std::uint32_t function_local_count = 0;
        std::vector<std::pair<std::uint32_t, std::uint8_t>> local_groups;
        local_groups.reserve(groups);
        for (std::uint32_t group = 0; group < groups; ++group) {
            std::uint32_t locals = 0;
            std::uint8_t type = 0;
            if (!body.uleb(locals) || !body.value_type(&type)) return false;
            local_total += locals;
            if (local_total > 10'000'000 || locals > UINT32_MAX - function_local_count) return false;
            function_local_count += locals;
            local_groups.push_back({locals, type});
        }
        const auto code_size = body.bytes.size() - body.position;
        if (!code_size || body.bytes.back() != std::byte{0x0b}) return false;
        const auto code_offset = section_file_offset + r.position + body.position;
        bodies.push_back({imported_count + n, code_offset, code_size, function_local_count,
                          std::move(local_groups)});
        if (!r.skip(body_size)) return false;
    }
    return r.position == r.bytes.size();
}

// Validate the MVP stack machine independently of the disassembler's fixed-size
// instruction representation. This also validates unreachable code: only operand
// underflow becomes polymorphic after a terminating instruction.
bool validate_body(const FunctionBody &body, std::span<const std::byte> module,
                   const WasmMetadata &metadata, const std::vector<GlobalType> &globals,
                   std::stop_token stop, std::string &reason, bool &unsupported,
                   bool &canceled, bool &limited) {
    const auto type_index = metadata.function_type_indices[body.index];
    const auto &signature = metadata.function_types[type_index];
    Reader code{module.subspan(static_cast<std::size_t>(body.code_offset),
                               static_cast<std::size_t>(body.code_size))};
    struct Frame {
        std::uint8_t kind;
        std::vector<std::uint8_t> parameters, results;
        std::size_t height;
        bool unreachable = false, has_else = false;
    };
    std::vector<Frame> controls{{0xff, {}, signature.result_types, 0}};
    std::vector<std::uint8_t> stack;
    const auto fail = [&](const char *message) { reason = "function[" + std::to_string(body.index) +
        "] at operator byte " + std::to_string(code.position ? code.position - 1 : 0) + ": " + message; return false; };
    const auto push = [&](std::uint8_t type) {
        if (stack.size() >= max_wasm_operand_stack) { limited = true; return false; }
        stack.push_back(type);
        return true;
    };
    const auto pop = [&](std::uint8_t expected) {
        const auto &frame = controls.back();
        if (stack.size() == frame.height) return frame.unreachable;
        const auto actual = stack.back();
        stack.pop_back();
        return !expected || !actual || actual == expected;
    };
    const auto pop_any = [&]() -> std::uint8_t {
        const auto &frame = controls.back();
        if (stack.size() == frame.height) return 0;
        const auto value = stack.back(); stack.pop_back(); return value;
    };
    const auto dead = [&]() {
        stack.resize(controls.back().height);
        controls.back().unreachable = true;
    };
    const auto label = [&](std::uint32_t depth) -> const std::vector<std::uint8_t> & {
        const auto &target = controls[controls.size() - 1 - depth];
        return target.kind == 0x03 ? target.parameters : target.results;
    };
    const auto pop_types = [&](const std::vector<std::uint8_t> &types) {
        for (auto it = types.rbegin(); it != types.rend(); ++it)
            if (!pop(*it)) return false;
        return true;
    };
    const auto local_type = [&](std::uint32_t index) -> std::uint8_t {
        if (index < signature.parameter_types.size()) return signature.parameter_types[index];
        index -= signature.parameter_count;
        for (const auto &[count, type] : body.local_groups) {
            if (index < count) return type;
            index -= count;
        }
        return 0;
    };
    std::size_t operator_count = 0;
    while (code.position < code.bytes.size()) {
        if ((operator_count++ & 0xfff) == 0 && stop.stop_requested()) {
            canceled = true;
            return fail("validation canceled");
        }
        const auto op_begin = code.position;
        std::uint8_t op = 0;
        if (!code.byte(op)) return fail("truncated opcode");
        std::uint32_t index = 0;
        if (op == 0x00 || op == 0x0c || op == 0x0f) {
            if (op == 0x0c && (!code.uleb(index) || index >= controls.size())) return fail("invalid branch depth");
            if (op == 0x0f && !pop_types(controls.front().results)) return fail("return type mismatch");
            if (op == 0x0c && !pop_types(label(index))) return fail("branch type mismatch");
            dead();
        } else if (op == 0x01) {
        } else if (op >= 0x02 && op <= 0x04) {
            std::int64_t block_type = 0;
            if (!code.sleb(33, block_type)) return fail("invalid or truncated block type");
            std::vector<std::uint8_t> parameters, results;
            if (block_type == -1) results.push_back(0x7f);
            else if (block_type == -2) results.push_back(0x7e);
            else if (block_type == -3) results.push_back(0x7d);
            else if (block_type == -4) results.push_back(0x7c);
            else if (block_type != -64) {
                if (block_type < 0 || static_cast<std::uint64_t>(block_type) >= metadata.function_types.size())
                    return fail("block type index is out of range");
                const auto &block_signature = metadata.function_types[static_cast<std::size_t>(block_type)];
                parameters = block_signature.parameter_types;
                results = block_signature.result_types;
            }
            if (results.size() > max_wasm_multi_values) {
                unsupported = true;
                return fail("block result vector exceeds the 128-value multi-value limit");
            }
            if (op == 0x04 && !pop(0x7f)) return fail("if condition must be i32");
            if (!pop_types(parameters)) return fail("block parameter type mismatch");
            if (controls.size() >= max_wasm_control_depth) {
                limited = true;
                return fail("control nesting limit exceeded");
            }
            const auto height = stack.size();
            controls.push_back({op, parameters, std::move(results), height,
                                controls.back().unreachable});
            for (auto parameter : parameters) if (!push(parameter)) return fail("operand stack limit exceeded");
        } else if (op == 0x05 || op == 0x0b) {
            if (controls.empty()) return fail("unmatched else or end");
            auto &frame = controls.back();
            if (op == 0x05 && (frame.kind != 0x04 || frame.has_else)) return fail("else without matching if");
            if (!pop_types(frame.results)) return fail("block result type mismatch");
            if (stack.size() != frame.height) return fail("block stack height mismatch");
            if (op == 0x05) {
                frame.has_else = true;
                stack.resize(frame.height);
                frame.unreachable = controls.size() > 1 && controls[controls.size() - 2].unreachable;
                for (auto type : frame.parameters) if (!push(type)) return fail("operand stack limit exceeded");
            } else {
                if (frame.kind == 0x04 && !frame.has_else && frame.parameters != frame.results)
                    return fail("if without else requires identical parameter and result types");
                const auto results = frame.results;
                controls.pop_back();
                if (controls.empty()) return code.position == code.bytes.size() || fail("bytes after function end");
                for (auto type : results) if (!push(type)) return fail("operand stack limit exceeded");
            }
        } else if (op == 0x0d) {
            if (!code.uleb(index) || index >= controls.size()) return fail("invalid branch depth");
            if (!pop(0x7f) || !pop_types(label(index)))
                return fail("conditional branch type mismatch");
            for (auto type : label(index)) if (!push(type)) return fail("operand stack limit exceeded");
        } else if (op == 0x0e) {
            std::uint32_t count = 0;
            std::vector<std::uint8_t> first;
            if (!code.uleb(count) || count > 8) { unsupported = true; return fail("branch table exceeds decoder limit"); }
            for (std::uint32_t n = 0; n <= count; ++n) {
                if (!code.uleb(index) || index >= controls.size()) return fail("invalid branch table depth");
                const auto &types = label(index);
                if (n == 0) first = types;
                else if (first != types) return fail("branch table target types differ");
            }
            if (!pop(0x7f) || !pop_types(first))
                return fail("branch table type mismatch");
            dead();
        } else if (op == 0x10 || op == 0x11) {
            if (!code.uleb(index)) return fail("invalid call index");
            const WasmFunctionType *callee = nullptr;
            if (op == 0x10) {
                if (index >= metadata.function_type_indices.size()) return fail("call index out of range");
                callee = &metadata.function_types[metadata.function_type_indices[index]];
            } else {
                std::uint8_t table = 0;
                if (!code.byte(table) || table != 0 || index >= metadata.function_types.size() ||
                    metadata.imported_tables + metadata.defined_tables != 1)
                    return fail("invalid indirect call type or table");
                if (!pop(0x7f)) return fail("indirect call table index must be i32");
                callee = &metadata.function_types[index];
            }
            for (auto it = callee->parameter_types.rbegin(); it != callee->parameter_types.rend(); ++it)
                if (!pop(*it)) return fail("call argument type mismatch");
            for (auto type : callee->result_types) if (!push(type)) return fail("operand stack limit exceeded");
        } else if (op == 0x1a) {
            if (!pop(0)) return fail("drop stack underflow");
        } else if (op == 0x1b) {
            if (!pop(0x7f)) return fail("select condition must be i32");
            const auto rhs = pop_any(), lhs = pop_any();
            if ((rhs && lhs && rhs != lhs) || (stack.size() == controls.back().height &&
                !controls.back().unreachable && (!rhs || !lhs))) return fail("select operands differ or underflow");
            if (!push(lhs ? lhs : rhs)) return fail("operand stack limit exceeded");
        } else if (op >= 0x20 && op <= 0x24) {
            if (!code.uleb(index)) return fail("invalid local or global index");
            if (op <= 0x22) {
                const auto type = local_type(index);
                if (!type) return fail("local index out of range");
                if (op != 0x20 && !pop(type)) return fail("local assignment type mismatch");
                if (op != 0x21 && !push(type)) return fail("operand stack limit exceeded");
            } else {
                if (index >= globals.size()) return fail("global index out of range");
                const auto &global = globals[index];
                if (op == 0x24 && (!global.mutable_value || !pop(global.value)))
                    return fail("global assignment requires matching mutable global");
                if (op == 0x23 && !push(global.value)) return fail("operand stack limit exceeded");
            }
        } else if (op >= 0x28 && op <= 0x3e) {
            static constexpr std::array<std::uint8_t, 23> alignment{
                2,3,2,3,0,0,1,1,0,0,1,1,2,2,2,3,2,3,0,1,0,1,2};
            if (metadata.imported_memories + metadata.defined_memories != 1)
                return fail("memory instruction requires one memory");
            std::uint32_t align = 0, offset = 0;
            if (!code.uleb(align) || !code.uleb(offset) || align > alignment[op - 0x28])
                return fail("invalid memory immediate or alignment");
            std::uint8_t type = op <= 0x35 ? (op == 0x29 || (op >= 0x30 && op <= 0x35) ? 0x7e :
                op == 0x2a ? 0x7d : op == 0x2b ? 0x7c : 0x7f) :
                (op == 0x37 || op >= 0x3c ? 0x7e : op == 0x38 ? 0x7d : op == 0x39 ? 0x7c : 0x7f);
            if (op >= 0x36 && !pop(type)) return fail("store value type mismatch");
            if (!pop(0x7f)) return fail("memory address must be i32");
            if (op <= 0x35 && !push(type)) return fail("operand stack limit exceeded");
        } else if (op == 0x3f || op == 0x40) {
            std::uint8_t memory = 0;
            if (!code.byte(memory) || memory != 0 || metadata.imported_memories + metadata.defined_memories != 1)
                return fail("invalid memory size/grow memory index");
            if (op == 0x40 && !pop(0x7f)) return fail("memory.grow operand must be i32");
            if (!push(0x7f)) return fail("operand stack limit exceeded");
        } else if (op >= 0x41 && op <= 0x44) {
            if (op == 0x41 || op == 0x42) {
                if (!code.sleb(op == 0x41 ? 32 : 64)) return fail("invalid integer constant");
            } else if (!code.skip(op == 0x43 ? 4 : 8)) return fail("truncated float constant");
            if (!push(op == 0x41 ? 0x7f : op == 0x42 ? 0x7e : op == 0x43 ? 0x7d : 0x7c))
                return fail("operand stack limit exceeded");
        } else if (op >= 0x45 && op <= 0xbf) {
            std::uint8_t input = 0, output = 0;
            bool binary = true;
            if (op <= 0x4f) { input = 0x7f; output = 0x7f; binary = op != 0x45; }
            else if (op <= 0x5a) { input = 0x7e; output = 0x7f; binary = op != 0x50; }
            else if (op <= 0x60) { input = 0x7d; output = 0x7f; }
            else if (op <= 0x66) { input = 0x7c; output = 0x7f; }
            else if (op <= 0x78) { input = output = 0x7f; binary = op > 0x69; }
            else if (op <= 0x8a) { input = output = 0x7e; binary = op > 0x7b; }
            else if (op <= 0x98) { input = output = 0x7d; binary = op > 0x91; }
            else if (op <= 0xa6) { input = output = 0x7c; binary = op > 0x9f; }
            else {
                static constexpr std::array<std::uint8_t, 25> inputs{
                    0x7e,0x7d,0x7d,0x7c,0x7c,0x7f,0x7f,0x7d,0x7d,0x7c,0x7c,
                    0x7f,0x7f,0x7e,0x7e,0x7c,0x7f,0x7f,0x7e,0x7e,0x7d,0x7d,0x7c,0x7f,0x7e};
                static constexpr std::array<std::uint8_t, 25> outputs{
                    0x7f,0x7f,0x7f,0x7f,0x7f,0x7e,0x7e,0x7e,0x7e,0x7e,0x7e,
                    0x7d,0x7d,0x7d,0x7d,0x7d,0x7c,0x7c,0x7c,0x7c,0x7c,0x7f,0x7e,0x7d,0x7c};
                input = inputs[op - 0xa7]; output = outputs[op - 0xa7]; binary = false;
            }
            if (!pop(input) || (binary && !pop(input))) return fail("numeric operand type mismatch");
            if (!push(output)) return fail("operand stack limit exceeded");
        } else {
            unsupported = true; return fail("opcode outside WebAssembly MVP scalar subset");
        }
        if (code.position - op_begin > 15) { unsupported = true; return fail("instruction exceeds 15-byte decoder limit"); }
    }
    return fail("missing function end");
}
}

Result<LoadedImage> load_wasm(std::shared_ptr<const ByteStorage> storage, std::stop_token stop) {
    if (!storage) return Error{ErrorCode::invalid_argument, "WebAssembly loader requires input storage"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly loading canceled"};
    if (storage->size() < 8) return Error{ErrorCode::malformed, "Truncated WebAssembly module header"};
    if (storage->size() > max_input_bytes || storage->size() > SIZE_MAX)
        return Error{ErrorCode::resource_limit, "WebAssembly module exceeds the 256 MiB parser limit"};
    try {
    auto view = storage->read_at({0}, static_cast<std::size_t>(storage->size()));
    if (!view) return view.error();
    if (view.value().bytes.size() != storage->size())
        return Error{ErrorCode::io, "WebAssembly source returned an incomplete read"};
    const auto bytes = std::span<const std::byte>(view.value().bytes);
    constexpr std::array<std::byte, 8> header{
        std::byte{0x00}, std::byte{0x61}, std::byte{0x73}, std::byte{0x6d},
        std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    if (!std::equal(header.begin(), header.end(), bytes.begin()))
        return Error{ErrorCode::malformed, "Unsupported WebAssembly magic or binary version"};
    std::vector<std::uint32_t> function_types;
    std::vector<FunctionBody> bodies;
    std::vector<GlobalType> globals;
    WasmMetadata wasm;
    std::vector<Diagnostic> wasm_diagnostics;
    std::uint64_t name_bytes = 0;
    std::uint32_t type_count = 0;
    std::string parse_reason;
    bool unsupported_payload = false;
    std::array<bool, 13> seen{};
    std::array<bool, 13> warned_section{};
    bool warned_custom = false;
    int previous_order = 0;
    Reader module{bytes, 8};
    while (module.position < bytes.size()) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly loading canceled"};
        std::uint8_t id = 0;
        std::uint32_t section_size = 0;
        if (!module.byte(id))
            return Error{ErrorCode::malformed, "Truncated WebAssembly section id"};
        if (id > 12)
            return Error{ErrorCode::unsupported, "Unsupported WebAssembly section id " + std::to_string(id)};
        if (!module.uleb(section_size) || section_size > bytes.size() - module.position)
            return Error{ErrorCode::malformed, "Invalid WebAssembly section header or extent"};
        const auto section_begin = module.position;
        Reader section{bytes.subspan(section_begin, section_size)};
        if (id != 0) {
            const auto order = section_order(id);
            if (order < 0 || seen[id] || order <= previous_order)
                return Error{ErrorCode::malformed, "WebAssembly sections are duplicated or out of order"};
            seen[id] = true;
            previous_order = order;
        }
        bool valid = true;
        if (id == 1) valid = parse_types(section, type_count, wasm, parse_reason, unsupported_payload);
        else if (id == 2) {
            valid = parse_imports(section, type_count, wasm, section_begin, name_bytes,
                                  parse_reason, unsupported_payload);
            if (valid) for (const auto &entry : wasm.imports)
                if (entry.kind == WasmExternalKind::global) {
                    globals.push_back({*entry.global_value_type, entry.global_mutable});
                    wasm.globals.push_back({*entry.global_value_type, entry.global_mutable, true});
                }
        }
        else if (id == 3) valid = parse_functions(section, type_count, function_types);
        else if (id == 4) valid = parse_tables(section, wasm.defined_tables, wasm, parse_reason, unsupported_payload);
        else if (id == 5) valid = parse_memories(section, wasm.defined_memories, wasm, parse_reason, unsupported_payload);
        else if (id == 6) valid = parse_globals(section, wasm.defined_globals, wasm.imported_globals, globals, wasm,
                                                parse_reason, unsupported_payload);
        else if (id == 7) valid = parse_exports(section, wasm, section_begin, name_bytes, parse_reason, unsupported_payload);
        else if (id == 8) valid = parse_start(section, wasm, section_begin, parse_reason);
        else if (id == 9) valid = parse_elements(section, wasm, section_begin, parse_reason, unsupported_payload);
        else if (id == 11) valid = parse_data(section, wasm, section_begin, parse_reason, unsupported_payload);
        else if (id == 12) valid = parse_data_count(section, wasm, parse_reason);
        else if (id == 10) valid = parse_code(section, wasm.imported_functions, bodies, section_begin);
        else if (id == 0) {
            std::string custom_name;
            valid = section.name(custom_name, name_bytes);
            if (valid && custom_name == "name") {
                valid = parse_name_section(section, section_begin, wasm, name_bytes, parse_reason);
            } else if (valid && !warned_custom) {
                warned_custom = true;
                wasm_diagnostics.push_back({DiagnosticSeverity::info,
                    "WebAssembly custom section '" + custom_name + "' payload is retained by the source but not interpreted", {}});
            }
        } else {
            if (!warned_section[id]) {
                warned_section[id] = true;
                wasm_diagnostics.push_back({DiagnosticSeverity::info,
                    "WebAssembly " + std::string(unparsed_section_name(id)) + " section (id " +
                        std::to_string(id) + ") is extent-checked but not interpreted", {}});
            }
        }
        if (!valid) {
            const auto detail = parse_reason.empty() ? "malformed WebAssembly section payload" : parse_reason;
            return Error{unsupported_payload ? ErrorCode::unsupported : ErrorCode::malformed,
                         (unsupported_payload ? "Unsupported WebAssembly content: " : "Malformed WebAssembly content: ") + detail};
        }
        module.position += section_size;
    }
    if (function_types.size() != bodies.size())
        return Error{ErrorCode::malformed, "WebAssembly function and code section counts do not match"};
    if (bodies.size() >= max_vector_items)
        return Error{ErrorCode::resource_limit, "WebAssembly function count exceeds the address-space limit"};
    if (static_cast<std::uint64_t>(wasm.imported_functions) + function_types.size() > max_vector_items ||
        static_cast<std::uint64_t>(wasm.imported_tables) + wasm.defined_tables > max_vector_items ||
        static_cast<std::uint64_t>(wasm.imported_memories) + wasm.defined_memories > max_vector_items ||
        static_cast<std::uint64_t>(wasm.imported_globals) + wasm.defined_globals > max_vector_items)
        return Error{ErrorCode::resource_limit, "WebAssembly external index space exceeds the one-million-item limit"};
    if (static_cast<std::uint64_t>(wasm.imported_memories) + wasm.defined_memories > 1)
        return Error{ErrorCode::unsupported, "Multiple WebAssembly memories require the multi-memory proposal"};
    if (wasm.declared_data_count && *wasm.declared_data_count != wasm.data_segments.size())
        return Error{ErrorCode::malformed, "WebAssembly data-count does not match the data section"};
    for (const auto &segment : wasm.data_segments) {
        if (segment.mode == WasmDataMode::active &&
            segment.memory_index >= static_cast<std::uint64_t>(wasm.imported_memories) + wasm.defined_memories)
            return Error{ErrorCode::malformed, "WebAssembly active data segment references a missing memory"};
        if (segment.mode == WasmDataMode::active && segment.offset_kind == WasmOffsetExpressionKind::global_get &&
            segment.offset_value >= static_cast<std::uint64_t>(wasm.imported_globals) + wasm.defined_globals)
            return Error{ErrorCode::malformed, "WebAssembly data segment offset references a missing global"};
    }
    for (const auto &segment : wasm.element_segments) {
        if (segment.mode == WasmElementMode::active && segment.offset_kind == WasmOffsetExpressionKind::global_get &&
            segment.offset_value >= static_cast<std::uint64_t>(wasm.imported_globals) + wasm.defined_globals)
            return Error{ErrorCode::malformed, "WebAssembly element segment offset references a missing global"};
    }
    if (static_cast<std::uint64_t>(wasm.imported_tables) + wasm.defined_tables > 1)
        return Error{ErrorCode::unsupported, "Multiple WebAssembly tables require an extension outside this loader's subset"};
    wasm.type_count = type_count;
    wasm.defined_functions = static_cast<std::uint32_t>(function_types.size());
    wasm.function_type_indices.insert(wasm.function_type_indices.end(), function_types.begin(), function_types.end());
    std::size_t retained_local_types = 0;
    wasm.function_locals.reserve(bodies.size());
    for (const auto &body : bodies) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly body validation canceled"};
        parse_reason.clear(); unsupported_payload = false;
        bool canceled = false, limited = false;
        if (!validate_body(body, bytes, wasm, globals, stop, parse_reason,
                           unsupported_payload, canceled, limited))
            return Error{canceled ? ErrorCode::canceled : limited ? ErrorCode::resource_limit :
                         unsupported_payload ? ErrorCode::unsupported : ErrorCode::malformed,
                         "WebAssembly body validation failed: " + parse_reason};
        if (body.local_count > max_vector_items - retained_local_types)
            return Error{ErrorCode::resource_limit, "WebAssembly expanded local metadata exceeds the one-million-type limit"};
        WasmFunctionLocals locals;
        locals.function_index = body.index;
        locals.value_types.reserve(body.local_count);
        for (const auto &[count, type] : body.local_groups)
            locals.value_types.insert(locals.value_types.end(), count, type);
        retained_local_types += locals.value_types.size();
        wasm.function_locals.push_back(std::move(locals));
    }
    auto table_applied = apply_initial_table_elements(wasm, wasm_diagnostics);
    if (!table_applied) return table_applied.error();
    if (wasm.start_function) {
        const auto index = wasm.start_function->function_index;
        if (index >= wasm.function_type_indices.size())
            return Error{ErrorCode::malformed, "WebAssembly start function index is outside the function index space"};
        const auto type_index = wasm.function_type_indices[index];
        if (type_index >= wasm.function_types.size())
            return Error{ErrorCode::malformed, "WebAssembly start function has an invalid function type index"};
        const auto &type = wasm.function_types[type_index];
        if (type.parameter_count != 0 || type.result_count != 0)
            return Error{ErrorCode::malformed, "WebAssembly start function must have type [] -> []"};
        wasm.start_function->function_type_index = type_index;
    }
    // Build descriptors in kind-specific index order. Imports are retained in
    // source order, but each kind's index is assigned monotonically as it is
    // parsed, so filtering imports preserves the corresponding index order.
    std::vector<WasmLimits> table_limits;
    std::vector<WasmLimits> memory_limits;
    table_limits.reserve(static_cast<std::size_t>(wasm.imported_tables) + wasm.defined_tables);
    memory_limits.reserve(static_cast<std::size_t>(wasm.imported_memories) + wasm.defined_memories);
    for (const auto &entry : wasm.imports) {
        if (entry.kind == WasmExternalKind::table) {
            if (!entry.limits) return Error{ErrorCode::malformed, "WebAssembly table import has no limits"};
            table_limits.push_back(*entry.limits);
        } else if (entry.kind == WasmExternalKind::memory) {
            if (!entry.limits) return Error{ErrorCode::malformed, "WebAssembly memory import has no limits"};
            memory_limits.push_back(*entry.limits);
        }
    }
    table_limits.insert(table_limits.end(), wasm.defined_table_limits.begin(), wasm.defined_table_limits.end());
    memory_limits.insert(memory_limits.end(), wasm.defined_memory_limits.begin(), wasm.defined_memory_limits.end());
    for (auto &entry : wasm.exports) {
        std::uint64_t count = 0;
        switch (entry.kind) {
        case WasmExternalKind::function:
            count = wasm.function_type_indices.size();
            if (entry.index < count) entry.function_type_index = wasm.function_type_indices[entry.index];
            break;
        case WasmExternalKind::table:
            count = table_limits.size();
            if (entry.index < count) entry.limits = table_limits[entry.index];
            break;
        case WasmExternalKind::memory:
            count = memory_limits.size();
            if (entry.index < count) entry.limits = memory_limits[entry.index];
            break;
        case WasmExternalKind::global:
            count = wasm.globals.size();
            if (entry.index < count) {
                entry.global_value_type = wasm.globals[entry.index].value_type;
                entry.global_mutable = wasm.globals[entry.index].mutable_value;
            }
            break;
        }
        if (entry.index >= count)
            return Error{ErrorCode::malformed, "WebAssembly export index is outside its kind-specific index space"};
    }
    std::vector<std::uint32_t> local_counts(wasm.function_type_indices.size());
    for (const auto &body : bodies) local_counts[body.index] = body.local_count;
    std::set<std::uint32_t> named_functions;
    for (const auto &name : wasm.function_names) {
        if (name.function_index >= wasm.function_type_indices.size())
            return Error{ErrorCode::malformed, "WebAssembly function name index is outside the function index space"};
        if (!named_functions.insert(name.function_index).second)
            return Error{ErrorCode::malformed, "WebAssembly function index has more than one name"};
    }
    std::set<std::pair<std::uint32_t, std::uint32_t>> named_locals;
    for (const auto &name : wasm.local_names) {
        if (name.function_index >= wasm.function_type_indices.size())
            return Error{ErrorCode::malformed, "WebAssembly local name function index is outside the function index space"};
        const auto type_index = wasm.function_type_indices[name.function_index];
        if (type_index >= wasm.function_types.size())
            return Error{ErrorCode::malformed, "WebAssembly local name function has an invalid type index"};
        const auto parameter_count = wasm.function_types[type_index].parameter_count;
        const auto max_locals = static_cast<std::uint64_t>(parameter_count) + local_counts[name.function_index];
        if (name.local_index >= max_locals)
            return Error{ErrorCode::malformed, "WebAssembly local name index exceeds parameters and declared locals"};
        if (!named_locals.insert({name.function_index, name.local_index}).second)
            return Error{ErrorCode::malformed, "WebAssembly local index has more than one name"};
    }
    ImageLayout layout{{{0}, 32, 1, ByteOrder::little}, Architecture::wasm, ExecutionMode::wasm32, {}, {}};
    layout.segments.reserve(bodies.size());
    layout.entries.reserve(bodies.size());
    layout.domains.reserve(bodies.size() ? bodies.size() - 1 : 0);
    for (std::size_t i = 0; i < bodies.size(); ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly function mapping canceled"};
        const auto &body = bodies[i];
        const AddressSpaceId id{body.index};
        const DecodeContext context{Architecture::wasm, ExecutionMode::wasm32, ByteOrder::little};
        if (id.value != 0)
            layout.domains.push_back({AddressSpace{id, 32, 1, ByteOrder::little}, context});
        const Address begin{id, 0};
        const auto function_name = std::find_if(wasm.function_names.begin(), wasm.function_names.end(),
            [&](const WasmFunctionName &name) { return name.function_index == body.index; });
        const auto segment_name = function_name == wasm.function_names.end()
            ? "function[" + std::to_string(body.index) + "]" : function_name->name;
        layout.segments.push_back({segment_name, begin,
                                   body.code_size, {body.code_offset}, body.code_size,
                                   true, false, true});
        layout.entries.push_back(begin);
    }
    auto memory_mapped = map_linear_memory(wasm, layout, wasm_diagnostics, stop);
    if (!memory_mapped) return memory_mapped.error();
    auto image = Image::create(std::move(storage), std::move(layout));
    if (!image) return image.error();
    LoadedImage loaded;
    loaded.image = std::move(image.value());
    loaded.metadata.format = "WebAssembly v1 (wasm32)";
    loaded.metadata.image_size = bytes.size();
    loaded.metadata.wasm = std::move(wasm);
    loaded.metadata_complete = false;
    loaded.diagnostics.push_back({DiagnosticSeverity::info,
        "Function bodies are MVP type-validated and mapped to function-relative address spaces; host linking is not implemented", {}});
    loaded.diagnostics.insert(loaded.diagnostics.end(), wasm_diagnostics.begin(), wasm_diagnostics.end());
    auto read = loaded.metadata_reads.include({0}, bytes.size());
    if (!read) return read.error();
    return loaded;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate WebAssembly parser state"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "WebAssembly parser state exceeds container limits"};
    }
}
} // namespace hexlab
