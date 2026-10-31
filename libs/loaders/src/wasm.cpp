#include "hexlab/loaders/wasm.hpp"
#include "hexlab/processors/wasm_simd_integer.hpp"
#include <algorithm>
#include <array>
#include <bit>
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
constexpr std::uint32_t max_wasm_producer_fields = 64;
constexpr std::uint32_t max_wasm_producer_values = 4096;
constexpr std::uint32_t max_wasm_target_features = 4096;
constexpr std::uint32_t max_wasm_custom_sections = 65536;
constexpr std::uint32_t max_wasm_linking_segments = 65536;
constexpr std::uint32_t max_wasm_linking_symbols = 1'000'000;
constexpr std::uint64_t max_wasm_dylink_opaque_bytes = 4u * 1024u * 1024u;
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
        if (type != 0x7f && type != 0x7e && type != 0x7d && type != 0x7c &&
            type != 0x70 && type != 0x6f) return false;
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
    bool limits(bool memory, WasmLimits &result, bool *memory64 = nullptr) {
        std::uint32_t flags = 0, minimum = 0, maximum = 0;
        if (!uleb(flags)) return false;
        if (memory && (flags & 0x4)) {
            if (memory64) *memory64 = true;
            return false;
        }
        if ((flags & ~(memory ? std::uint32_t{0x3} : std::uint32_t{0x1})) || !uleb(minimum)) return false;
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

bool integer_constant_operator(std::uint8_t opcode, std::uint8_t &input_type,
                               std::uint8_t &result_type, unsigned &arity) {
    if (opcode == 0x45) { input_type = 0x7f; result_type = 0x7f; arity = 1; return true; }
    if (opcode == 0x50) { input_type = 0x7e; result_type = 0x7f; arity = 1; return true; }
    if (opcode >= 0x67 && opcode <= 0x69) { input_type = result_type = 0x7f; arity = 1; return true; }
    if (opcode >= 0x79 && opcode <= 0x7b) { input_type = result_type = 0x7e; arity = 1; return true; }
    if ((opcode >= 0x6a && opcode <= 0x6c) || (opcode >= 0x71 && opcode <= 0x78)) {
        input_type = result_type = 0x7f; arity = 2; return true;
    }
    if ((opcode >= 0x7c && opcode <= 0x7e) || (opcode >= 0x83 && opcode <= 0x8a)) {
        input_type = result_type = 0x7e; arity = 2; return true;
    }
    if (opcode == 0xa7) { input_type = 0x7e; result_type = 0x7f; arity = 1; return true; }
    if (opcode == 0xac || opcode == 0xad) { input_type = 0x7f; result_type = 0x7e; arity = 1; return true; }
    if (opcode >= 0xc0 && opcode <= 0xc1) { input_type = result_type = 0x7f; arity = 1; return true; }
    if (opcode >= 0xc2 && opcode <= 0xc4) { input_type = result_type = 0x7e; arity = 1; return true; }
    return false;
}

std::uint64_t apply_integer_constant_operator(std::uint8_t opcode, std::uint64_t left,
                                             std::optional<std::uint64_t> right = {}) {
    if (opcode == 0x45) return static_cast<std::uint32_t>(left) == 0;
    if (opcode == 0x50) return left == 0;
    if (opcode >= 0x67 && opcode <= 0x69) {
        const auto value = static_cast<std::uint32_t>(left);
        if (opcode == 0x67) return std::countl_zero(value);
        if (opcode == 0x68) return std::countr_zero(value);
        return std::popcount(value);
    }
    if (opcode >= 0x79 && opcode <= 0x7b) {
        if (opcode == 0x79) return std::countl_zero(left);
        if (opcode == 0x7a) return std::countr_zero(left);
        return std::popcount(left);
    }
    if (opcode == 0xa7) return static_cast<std::uint32_t>(left);
    if (opcode == 0xac || opcode == 0xad) {
        const auto value = static_cast<std::uint32_t>(left);
        return opcode == 0xac && (value & 0x80000000u)
            ? (std::uint64_t{0xffffffff00000000} | value) : value;
    }
    if (opcode >= 0xc0 && opcode <= 0xc4) {
        const unsigned width = opcode == 0xc0 || opcode == 0xc2 ? 8u
                             : opcode == 0xc1 || opcode == 0xc3 ? 16u : 32u;
        const unsigned result_width = opcode <= 0xc1 ? 32u : 64u;
        const auto mask = (std::uint64_t{1} << width) - 1;
        const auto value = left & mask;
        const auto extended = (value & (std::uint64_t{1} << (width - 1)))
            ? value | (~std::uint64_t{0} << width) : value;
        return result_width == 32 ? static_cast<std::uint32_t>(extended) : extended;
    }
    if (!right) return 0;
    const auto b = *right;
    if (opcode <= 0x78) {
        const auto a32 = static_cast<std::uint32_t>(left);
        const auto b32 = static_cast<std::uint32_t>(b);
        const unsigned shift = b32 & 31u;
        switch (opcode) {
        case 0x6a: return static_cast<std::uint32_t>(a32 + b32);
        case 0x6b: return static_cast<std::uint32_t>(a32 - b32);
        case 0x6c: return static_cast<std::uint32_t>(a32 * b32);
        case 0x71: return a32 & b32;
        case 0x72: return a32 | b32;
        case 0x73: return a32 ^ b32;
        case 0x74: return static_cast<std::uint32_t>(a32 << shift);
        case 0x75: {
            const auto logical = a32 >> shift;
            return shift && (a32 & 0x80000000u) ? logical | (~std::uint32_t{0} << (32 - shift)) : logical;
        }
        case 0x76: return a32 >> shift;
        case 0x77: return std::rotl(a32, static_cast<int>(shift));
        case 0x78: return std::rotr(a32, static_cast<int>(shift));
        default: return 0;
        }
    }
    const unsigned shift = static_cast<unsigned>(b & 63u);
    switch (opcode) {
    case 0x7c: return left + b;
    case 0x7d: return left - b;
    case 0x7e: return left * b;
    case 0x83: return left & b;
    case 0x84: return left | b;
    case 0x85: return left ^ b;
    case 0x86: return left << shift;
    case 0x87: {
        const auto logical = left >> shift;
        return shift && (left & 0x8000000000000000ull) ? logical | (~std::uint64_t{0} << (64 - shift)) : logical;
    }
    case 0x88: return left >> shift;
    case 0x89: return std::rotl(left, static_cast<int>(shift));
    case 0x8a: return std::rotr(left, static_cast<int>(shift));
    default: return 0;
    }
}
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
            bool memory64 = false;
            if (!r.limits(true, limits, &memory64)) {
                if (memory64) { unsupported = true; reason = "memory64 imports are unsupported by the wasm32 loader"; }
                else reason = "invalid memory import limits";
                return false;
            }
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

bool parse_producers(Reader &r, std::uint64_t section_file_offset,
                     std::uint64_t &name_bytes, std::vector<WasmProducer> &producers,
                     std::string &reason) {
    std::uint32_t field_count = 0;
    if (!r.uleb(field_count) || field_count > max_wasm_producer_fields) {
        reason = "invalid WebAssembly producers field count";
        return false;
    }
    std::vector<WasmProducer> parsed;
    std::set<std::string> fields;
    std::uint32_t total_values = 0;
    auto bounded_name_bytes = name_bytes;
    for (std::uint32_t field_index = 0; field_index < field_count; ++field_index) {
        const auto entry_offset = section_file_offset + r.position;
        std::string field;
        std::uint32_t value_count = 0;
        if (!r.name(field, bounded_name_bytes) || !r.uleb(value_count) ||
            value_count > max_wasm_producer_values - total_values) {
            reason = "invalid WebAssembly producers field or value count";
            return false;
        }
        if (!fields.insert(field).second) {
            reason = "duplicate WebAssembly producers field name";
            return false;
        }
        total_values += value_count;
        std::set<std::string> names;
        for (std::uint32_t value_index = 0; value_index < value_count; ++value_index) {
            WasmProducer producer;
            producer.field = field;
            producer.entry_file_offset = {entry_offset};
            if (!r.name(producer.name, bounded_name_bytes) ||
                !r.name(producer.version, bounded_name_bytes)) {
                reason = "invalid WebAssembly producer name or version";
                return false;
            }
            if (!names.insert(producer.name).second) {
                reason = "duplicate WebAssembly producer name in field";
                return false;
            }
            parsed.push_back(std::move(producer));
        }
    }
    if (r.position != r.bytes.size()) {
        reason = "trailing bytes in WebAssembly producers section";
        return false;
    }
    name_bytes = bounded_name_bytes;
    producers = std::move(parsed);
    return true;
}

bool parse_target_features(Reader &r, std::uint64_t section_file_offset,
                           std::uint64_t &name_bytes, std::vector<WasmTargetFeature> &features,
                           std::string &reason) {
    std::uint32_t count = 0;
    if (!r.uleb(count) || count > max_wasm_target_features) {
        reason = "invalid WebAssembly target_features count";
        return false;
    }
    std::vector<WasmTargetFeature> parsed;
    std::set<std::string> names;
    auto bounded_name_bytes = name_bytes;
    parsed.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto entry_offset = section_file_offset + r.position;
        std::uint8_t prefix = 0;
        WasmTargetFeature feature;
        if (!r.byte(prefix) || (prefix != '+' && prefix != '-') ||
            !r.name(feature.name, bounded_name_bytes)) {
            reason = "invalid WebAssembly target_features entry";
            return false;
        }
        if (!names.insert(feature.name).second) {
            reason = "duplicate WebAssembly target feature name";
            return false;
        }
        feature.enabled = prefix == '+';
        feature.entry_file_offset = {entry_offset};
        parsed.push_back(std::move(feature));
    }
    if (r.position != r.bytes.size()) {
        reason = "trailing bytes in WebAssembly target_features section";
        return false;
    }
    name_bytes = bounded_name_bytes;
    features = std::move(parsed);
    return true;
}

bool parse_dylink_info(Reader &section, std::uint64_t section_file_offset,
                       std::uint64_t &name_bytes, WasmDylinkInfo &output,
                       std::string &reason) {
    WasmDylinkInfo parsed;
    parsed.section_file_offset = {section_file_offset};
    auto bounded_name_bytes = name_bytes;
    std::set<std::uint8_t> seen_singletons;
    std::uint64_t opaque_bytes = 0;
    std::uint64_t rows = 0;
    std::uint32_t subsection_count = 0;
    while (section.position < section.bytes.size()) {
        if (subsection_count++ >= max_vector_items) {
            reason = "WebAssembly dylink.0 subsection count exceeds the one-million-item limit";
            return false;
        }
        std::uint8_t id = 0;
        std::uint32_t size = 0;
        if (!section.byte(id) || !section.uleb(size) || size > section.bytes.size() - section.position) {
            reason = "invalid WebAssembly dylink.0 subsection header or extent";
            return false;
        }
        const auto entry_offset = section_file_offset + section.position;
        Reader subsection{section.bytes.subspan(section.position, size)};
        if (id == 1) {
            if (!seen_singletons.insert(id).second ||
                !subsection.uleb(parsed.memory_size) || !subsection.uleb(parsed.memory_alignment) ||
                !subsection.uleb(parsed.table_size) || !subsection.uleb(parsed.table_alignment) ||
                subsection.position != subsection.bytes.size()) {
                reason = "duplicate or malformed WebAssembly dylink.0 memory-info subsection";
                return false;
            }
            parsed.memory_info_present = true;
        } else if (id == 2 || id == 5) {
            std::uint32_t count = 0;
            if (!subsection.uleb(count) || count > max_vector_items - rows) {
                reason = "invalid WebAssembly dylink.0 string-list count";
                return false;
            }
            rows += count;
            for (std::uint32_t i = 0; i < count; ++i) {
                const auto string_offset = entry_offset + subsection.position;
                std::string value;
                if (!subsection.name(value, bounded_name_bytes)) {
                    reason = "invalid or over-budget WebAssembly dylink.0 string";
                    return false;
                }
                if (id == 2) parsed.needed.push_back({std::move(value), {string_offset}});
                else parsed.runtime_paths.push_back({std::move(value), {string_offset}});
            }
            if (subsection.position != subsection.bytes.size()) {
                reason = "trailing bytes in WebAssembly dylink.0 string-list subsection";
                return false;
            }
        } else if (id == 3 || id == 4) {
            std::uint32_t count = 0;
            if (!subsection.uleb(count) || count > max_vector_items - rows) {
                reason = "invalid WebAssembly dylink.0 symbol-info count";
                return false;
            }
            rows += count;
            for (std::uint32_t i = 0; i < count; ++i) {
                const auto symbol_offset = entry_offset + subsection.position;
                std::uint32_t flags = 0;
                if (id == 3) {
                    WasmDylinkExportInfo info;
                    if (!subsection.name(info.name, bounded_name_bytes) || !subsection.uleb(flags) ||
                        (flags & ~std::uint32_t{0x3f7u})) {
                        reason = "invalid WebAssembly dylink.0 export-info entry";
                        return false;
                    }
                    info.flags = flags;
                    info.entry_file_offset = {symbol_offset};
                    parsed.exports.push_back(std::move(info));
                } else {
                    WasmDylinkImportInfo info;
                    if (!subsection.name(info.module, bounded_name_bytes) ||
                        !subsection.name(info.name, bounded_name_bytes) || !subsection.uleb(flags) ||
                        (flags & ~std::uint32_t{0x3f7u})) {
                        reason = "invalid WebAssembly dylink.0 import-info entry";
                        return false;
                    }
                    info.flags = flags;
                    info.entry_file_offset = {symbol_offset};
                    parsed.imports.push_back(std::move(info));
                }
            }
            if (subsection.position != subsection.bytes.size()) {
                reason = "trailing bytes in WebAssembly dylink.0 symbol-info subsection";
                return false;
            }
        } else {
            if (size > max_wasm_dylink_opaque_bytes - opaque_bytes) {
                reason = "WebAssembly dylink.0 unknown subsection bytes exceed the 4 MiB limit";
                return false;
            }
            opaque_bytes += size;
            WasmDylinkOpaqueSubsection opaque;
            opaque.id = id;
            opaque.entry_file_offset = {entry_offset};
            opaque.payload.assign(subsection.bytes.begin(), subsection.bytes.end());
            parsed.unknown_subsections.push_back(std::move(opaque));
        }
        section.position += size;
    }
    name_bytes = bounded_name_bytes;
    output = std::move(parsed);
    return true;
}

bool parse_linking_segment_info(Reader &section, std::uint64_t section_file_offset,
                                std::uint64_t &name_bytes,
                                const WasmMetadata &metadata,
                                std::uint32_t defined_function_count,
                                std::vector<WasmLinkingSegmentInfo> &segments,
                                std::vector<WasmLinkingSymbol> &symbols,
                                bool &segment_info_present,
                                bool &symbol_table_present,
                                std::string &reason) {
    std::uint32_t version = 0;
    if (!section.uleb(version) || version != 2) {
        reason = "unsupported or truncated WebAssembly linking metadata version";
        return false;
    }
    std::set<std::uint8_t> seen_subsections;
    std::vector<WasmLinkingSegmentInfo> parsed;
    std::vector<WasmLinkingSymbol> parsed_symbols;
    std::uint32_t subsection_count = 0;
    auto bounded_name_bytes = name_bytes;
    while (section.position < section.bytes.size()) {
        if (subsection_count++ >= max_vector_items) {
            reason = "WebAssembly linking subsection count exceeds the one-million-item limit";
            return false;
        }
        std::uint8_t id = 0;
        std::uint32_t size = 0;
        if (!section.byte(id) || !section.uleb(size) || size > section.bytes.size() - section.position) {
            reason = "invalid WebAssembly linking subsection header or extent";
            return false;
        }
        Reader subsection{section.bytes.subspan(section.position, size)};
        const auto subsection_file_offset = section_file_offset + section.position;
        if (id == 5) {
            if (!seen_subsections.insert(id).second) {
                reason = "duplicate WebAssembly linking segment-info subsection";
                return false;
            }
            std::uint32_t count = 0;
            if (!subsection.uleb(count) || count > max_wasm_linking_segments) {
                reason = "invalid WebAssembly linking segment-info count";
                return false;
            }
            parsed.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) {
                WasmLinkingSegmentInfo item;
                item.segment_index = index;
                item.entry_file_offset = {subsection_file_offset + subsection.position};
                if (!subsection.name(item.name, bounded_name_bytes) ||
                    !subsection.uleb(item.alignment_log2) || item.alignment_log2 > 63 ||
                    !subsection.uleb(item.flags) || (item.flags & ~std::uint32_t{7})) {
                    reason = "invalid WebAssembly linking segment-info entry";
                    return false;
                }
                parsed.push_back(std::move(item));
            }
            if (subsection.position != subsection.bytes.size()) {
                reason = "trailing bytes in WebAssembly linking segment-info subsection";
                return false;
            }
            segment_info_present = true;
        } else if (id == 8) {
            if (!seen_subsections.insert(id).second) {
                reason = "duplicate WebAssembly linking symbol-table subsection";
                return false;
            }
            std::uint32_t count = 0;
            if (!subsection.uleb(count) || count > max_wasm_linking_symbols) {
                reason = "invalid WebAssembly linking symbol count";
                return false;
            }
            parsed_symbols.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) {
                WasmLinkingSymbol symbol;
                symbol.entry_file_offset = {subsection_file_offset + subsection.position};
                if (!subsection.byte(symbol.kind) || symbol.kind > 5 ||
                    !subsection.uleb(symbol.flags) || (symbol.flags & ~std::uint32_t{0x3f7u})) {
                    reason = "invalid WebAssembly linking symbol kind or flags";
                    return false;
                }
                const bool undefined = (symbol.flags & 0x10u) != 0;
                const bool explicit_name = (symbol.flags & 0x40u) != 0;
                const auto binding = symbol.flags & 3u;
                if (symbol.kind == 3) {
                    if (undefined || binding == 3 || !subsection.uleb(symbol.index)) {
                        reason = "invalid WebAssembly section symbol";
                        return false;
                    }
                    parsed_symbols.push_back(std::move(symbol));
                    continue;
                }
                if (symbol.kind == 1) {
                    if (binding == 3 && undefined) {
                        reason = "undefined WebAssembly data symbol cannot use common binding";
                        return false;
                    }
                    symbol.name.emplace();
                    if (!subsection.name(*symbol.name, bounded_name_bytes)) {
                        reason = "invalid WebAssembly linking data-symbol name";
                        return false;
                    }
                    if (!undefined) {
                        if (binding == 3) {
                            std::uint8_t alignment = 0;
                            symbol.data_size.emplace();
                            if (!subsection.uleb(*symbol.data_size) || !subsection.byte(alignment) || alignment > 31) {
                                reason = "invalid WebAssembly common data-symbol size or alignment";
                                return false;
                            }
                            symbol.common_alignment_log2 = alignment;
                        } else {
                            symbol.data_segment_index.emplace();
                            symbol.data_offset.emplace();
                            symbol.data_size.emplace();
                            if (!subsection.uleb(*symbol.data_segment_index) ||
                                !subsection.uleb(*symbol.data_offset) || !subsection.uleb(*symbol.data_size) ||
                                *symbol.data_segment_index >= metadata.data_segments.size()) {
                                reason = "WebAssembly data symbol references an invalid data segment";
                                return false;
                            }
                            const auto segment_size = metadata.data_segments[*symbol.data_segment_index].byte_count;
                            if (*symbol.data_offset > segment_size || *symbol.data_size > segment_size - *symbol.data_offset) {
                                reason = "WebAssembly data symbol exceeds its segment extent";
                                return false;
                            }
                        }
                    }
                } else {
                    if (!subsection.uleb(symbol.index)) {
                        reason = "truncated WebAssembly linking symbol index";
                        return false;
                    }
                    if (binding == 3) {
                        reason = "common binding is only valid for a defined WebAssembly data symbol";
                        return false;
                    }
                    const auto kind = symbol.kind == 0 ? WasmExternalKind::function :
                                      symbol.kind == 2 ? WasmExternalKind::global :
                                      symbol.kind == 5 ? WasmExternalKind::table : WasmExternalKind::function;
                    const auto imported_count = symbol.kind == 0 ? metadata.imported_functions :
                                                symbol.kind == 2 ? metadata.imported_globals :
                                                symbol.kind == 5 ? metadata.imported_tables : 0u;
                    const auto total_count = symbol.kind == 0 ?
                                                 std::uint64_t(metadata.imported_functions) + defined_function_count :
                                             symbol.kind == 2 ? metadata.imported_globals + metadata.defined_globals :
                                             symbol.kind == 5 ? metadata.imported_tables + metadata.defined_tables : 0u;
                    if (symbol.kind != 4 && symbol.index >= total_count) {
                        reason = "WebAssembly linking symbol index exceeds its module index space";
                        return false;
                    }
                    if (symbol.kind != 4 && undefined != (symbol.index < imported_count)) {
                        reason = "WebAssembly linking symbol undefined flag disagrees with import status";
                        return false;
                    }
                    if (undefined && binding == 2) {
                        reason = "local WebAssembly symbols cannot reference imports";
                        return false;
                    }
                    if (symbol.kind == 4 && undefined && !explicit_name) {
                        reason = "event imports without explicit names are unsupported in the loader metadata model";
                        return false;
                    }
                    if (!undefined || explicit_name) {
                        symbol.name.emplace();
                        if (!subsection.name(*symbol.name, bounded_name_bytes)) {
                            reason = "invalid WebAssembly linking symbol name";
                            return false;
                        }
                    } else {
                        const auto import = std::find_if(metadata.imports.begin(), metadata.imports.end(),
                            [&](const WasmImport &entry) { return entry.kind == kind && entry.index == symbol.index; });
                        if (import == metadata.imports.end()) {
                            reason = "WebAssembly linking import symbol has no matching import metadata";
                            return false;
                        }
                        symbol.import_module = import->module;
                        symbol.import_name = import->name;
                    }
                }
                parsed_symbols.push_back(std::move(symbol));
            }
            if (subsection.position != subsection.bytes.size()) {
                reason = "trailing bytes in WebAssembly linking symbol-table subsection";
                return false;
            }
            symbol_table_present = true;
        }
        section.position += size;
    }
    name_bytes = bounded_name_bytes;
    segments = std::move(parsed);
    symbols = std::move(parsed_symbols);
    return true;
}

bool parse_relocation_section(Reader &section, std::uint64_t section_file_offset,
        std::string_view name, std::span<const std::uint8_t> section_ids,
        std::span<const std::uint32_t> section_sizes, const WasmMetadata &wasm,
        bool linking_metadata_valid, std::size_t remaining_entries, std::stop_token stop,
        WasmRelocationSection &result, std::string &reason) {
    if (name.size() <= 6 || name.substr(0, 6) != "reloc.") {
        reason = "relocation section name must begin with reloc.";
        return false;
    }
    if (section_ids.empty() || section_ids.size() != section_sizes.size()) {
        reason = "WebAssembly section index table is inconsistent";
        return false;
    }
    std::uint32_t target = 0, count = 0;
    if (!section.uleb(target) || target >= section_ids.size() - 1 || !section.uleb(count) ||
        count > max_vector_items || count > remaining_entries) {
        reason = "invalid relocation target section or entry count";
        return false;
    }
    const auto target_id = section_ids[target];
    if (target_id != 0 && target_id != 10 && target_id != 11) {
        reason = "relocation target must be code, data, or a custom section";
        return false;
    }
    if (!linking_metadata_valid) {
        reason = "relocation section requires a valid preceding linking custom section";
        return false;
    }
    WasmRelocationSection parsed;
    parsed.name.assign(name);
    parsed.target_section_index = target;
    parsed.section_file_offset = {section_file_offset};
    parsed.entries.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        if ((i & 255u) == 0 && stop.stop_requested()) {
            reason = "WebAssembly relocation parsing canceled";
            return false;
        }
        const auto entry_offset = section_file_offset + section.position;
        std::uint8_t type = 0;
        std::uint32_t offset = 0, index = 0;
        if (!section.byte(type) || (type > 10 && type != 13) || !section.uleb(offset) || !section.uleb(index)) {
            reason = "unsupported or truncated relocation entry";
            return false;
        }
        const auto width = (type == 0 || type == 1 || type == 3 || type == 4 ||
                            type == 6 || type == 7 || type == 10) ? 5u : 4u;
        if (offset > section_sizes[target] || width > section_sizes[target] - offset) {
            reason = "relocation field exceeds its target section";
            return false;
        }
        if (type == 6) {
            if (index >= wasm.type_count) {
                reason = "type-index relocation references a missing type";
                return false;
            }
        } else {
            if (!wasm.linking_symbol_table_present || index >= wasm.linking_symbols.size()) {
                reason = "relocation references a missing linking symbol";
                return false;
            }
        }
        WasmRelocation row; row.type = type; row.offset = offset; row.index = index;
        row.entry_file_offset = {entry_offset};
        if (type == 3 || type == 4 || type == 5 || type == 8 || type == 9) {
            std::int64_t addend = 0;
            if (!section.sleb(32, addend)) {
                reason = "invalid signed 32-bit relocation addend";
                return false;
            }
            row.addend = static_cast<std::int32_t>(addend);
        }
        parsed.entries.push_back(std::move(row));
    }
    if (section.position != section.bytes.size()) {
        reason = "trailing bytes in relocation section";
        return false;
    }
    result = std::move(parsed);
    return true;
}

bool parse_name_section(Reader &section, std::uint64_t section_file_offset, WasmMetadata &metadata,
                        std::uint64_t &name_bytes, std::string &reason) {
    std::set<std::uint32_t> function_indices;
    std::set<std::pair<std::uint32_t, std::uint32_t>> local_indices;
    std::set<std::pair<std::uint32_t, std::uint32_t>> label_indices;
    std::set<std::uint32_t> label_function_indices;
    std::uint32_t subsection_count = 0;
    while (section.position < section.bytes.size()) {
        if (subsection_count >= max_vector_items) {
            reason = "WebAssembly name subsection count exceeds the one-million-item limit";
            return false;
        }
        ++subsection_count;
        std::uint8_t subsection_id = 0;
        std::uint32_t subsection_size = 0;
        if (!section.byte(subsection_id) || !section.uleb(subsection_size) ||
            subsection_size > section.bytes.size() - section.position) {
            reason = "invalid WebAssembly name subsection header or extent";
            return false;
        }
        Reader subsection{section.bytes.subspan(section.position, subsection_size)};
        const auto subsection_offset = section_file_offset + section.position;
        if (subsection_id == 0) {
            if (metadata.module_name) {
                reason = "duplicate WebAssembly module-name subsection";
                return false;
            }
            WasmModuleName item;
            item.entry_file_offset = {subsection_offset + subsection.position};
            if (!subsection.name(item.name, name_bytes) || subsection.position != subsection.bytes.size()) {
                reason = "invalid WebAssembly module-name subsection";
                return false;
            }
            metadata.module_name = std::move(item);
        } else if (subsection_id == 1) {
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
        } else if (subsection_id == 2 || subsection_id == 3) {
            std::uint32_t function_count = 0;
            if (!subsection.uleb(function_count) || function_count > max_vector_items) {
                reason = subsection_id == 2
                    ? "invalid WebAssembly local-name function count"
                    : "invalid WebAssembly label-name function count";
                return false;
            }
            for (std::uint32_t i = 0; i < function_count; ++i) {
                std::uint32_t function_index = 0, local_count = 0;
                const auto existing_count = subsection_id == 2
                    ? metadata.local_names.size() : metadata.label_names.size();
                if (!subsection.uleb(function_index) || !subsection.uleb(local_count) ||
                    local_count > max_vector_items || local_count > max_vector_items - existing_count) {
                    reason = subsection_id == 2
                        ? "invalid WebAssembly local-name map"
                        : "invalid WebAssembly label-name map";
                    return false;
                }
                if (subsection_id == 3) {
                    if (label_function_indices.size() >= max_vector_items) {
                        reason = "WebAssembly label-name function count exceeds the one-million-item limit";
                        return false;
                    }
                    if (!label_function_indices.insert(function_index).second) {
                        reason = "duplicate WebAssembly label-name function map";
                        return false;
                    }
                }
                for (std::uint32_t n = 0; n < local_count; ++n) {
                    if (subsection_id == 2) {
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
                    } else {
                        WasmLabelName item;
                        item.function_index = function_index;
                        item.entry_file_offset = {subsection_offset + subsection.position};
                        if (!subsection.uleb(item.label_index) || !subsection.name(item.name, name_bytes)) {
                            reason = "invalid WebAssembly label-name entry";
                            return false;
                        }
                        if (!label_indices.insert({item.function_index, item.label_index}).second) {
                            reason = "duplicate WebAssembly label-name index";
                            return false;
                        }
                        metadata.label_names.push_back(std::move(item));
                    }
                }
            }
            if (subsection.position != subsection.bytes.size()) {
                reason = subsection_id == 2
                    ? "trailing bytes in WebAssembly local-name subsection"
                    : "trailing bytes in WebAssembly label-name subsection";
                return false;
            }
        } else if (subsection_id >= 4 && subsection_id <= 9) {
            std::uint32_t count = 0;
            if (!subsection.uleb(count) || count > max_vector_items ||
                count > max_vector_items - metadata.index_names.size()) {
                reason = "invalid WebAssembly indexed-name map count";
                return false;
            }
            std::set<std::uint32_t> indices;
            for (const auto &existing : metadata.index_names)
                if (existing.subsection_id == subsection_id) indices.insert(existing.index);
            for (std::uint32_t i = 0; i < count; ++i) {
                WasmIndexName item;
                item.subsection_id = subsection_id;
                item.entry_file_offset = {subsection_offset + subsection.position};
                if (!subsection.uleb(item.index) || !subsection.name(item.name, name_bytes)) {
                    reason = "invalid WebAssembly indexed-name entry";
                    return false;
                }
                if (!indices.insert(item.index).second) {
                    reason = "duplicate WebAssembly indexed-name index";
                    return false;
                }
                metadata.index_names.push_back(std::move(item));
            }
            if (subsection.position != subsection.bytes.size()) {
                reason = "trailing bytes in WebAssembly indexed-name subsection";
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

bool parse_data_count(Reader &r, WasmMetadata &metadata, std::string &reason) {
    std::uint32_t count = 0;
    if (!r.uleb(count) || count > max_vector_items || r.position != r.bytes.size()) {
        reason = "invalid WebAssembly data-count section";
        return false;
    }
    metadata.declared_data_count = count;
    return true;
}

Result<WasmGlobalInitializer> parse_integer_initializer(Reader &, std::uint8_t,
    const std::vector<GlobalType> &, std::uint64_t, std::uint64_t &, std::stop_token);

bool supported_extended_i32_offset(const WasmGlobalInitializer &expression) {
    if (expression.kind != WasmGlobalInitializerKind::extended_integer) return true;
    return std::all_of(expression.instructions.begin(), expression.instructions.end(), [](const auto &item) {
        return item.opcode == 0x41 || item.opcode == 0x23 ||
               item.opcode == 0x6a || item.opcode == 0x6b || item.opcode == 0x6c;
    });
}

bool parse_data(Reader &r, WasmMetadata &metadata, std::uint64_t section_file_offset,
                const std::vector<GlobalType> &globals, std::uint64_t &instruction_work,
                std::stop_token stop, std::string &reason, bool &unsupported) {
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
            segment.offset_expression_file_offset = {section_file_offset + r.position - 1};
            --r.position; // Parse and validate the complete expression, including its terminator.
            auto expression = parse_integer_initializer(r, 0x7f, globals, section_file_offset,
                                                        instruction_work, stop);
            if (!expression) {
                unsupported = expression.error().code == ErrorCode::unsupported;
                reason = "invalid WebAssembly data segment offset expression: " + expression.error().message;
                return false;
            }
            auto parsed = std::move(expression.value());
            if (!supported_extended_i32_offset(parsed)) {
                unsupported = true;
                reason = "WebAssembly data offset expression uses an opcode outside extended-const i32 add/sub/mul";
                return false;
            }
            segment.evaluated_offset_value = parsed.evaluated_value_bits
                ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(*parsed.evaluated_value_bits))
                : std::nullopt;
            if (parsed.kind == WasmGlobalInitializerKind::numeric_constant) {
                segment.offset_kind = WasmOffsetExpressionKind::i32_constant;
                segment.offset_value = static_cast<std::uint32_t>(parsed.value);
                segment.offset_instructions.push_back({0x41, parsed.value,
                    segment.offset_expression_file_offset});
            } else if (parsed.kind == WasmGlobalInitializerKind::global_get) {
                segment.offset_kind = WasmOffsetExpressionKind::global_get;
                segment.offset_value = static_cast<std::uint32_t>(parsed.value);
                segment.offset_instructions.push_back({0x23, parsed.value,
                    segment.offset_expression_file_offset});
            } else {
                segment.offset_kind = WasmOffsetExpressionKind::extended_integer;
                segment.offset_instructions = std::move(parsed.instructions);
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
                    const std::vector<GlobalType> &globals, std::uint64_t &instruction_work,
                    std::stop_token stop, std::string &reason, bool &unsupported) {
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
        if (flags > 7) {
            unsupported = true;
            reason = "unsupported WebAssembly element segment encoding";
            return false;
        }
        const bool expressions = (flags & 4u) != 0;
        const bool active = (flags & 1u) == 0;
        if (!active && (flags & 2u)) segment.mode = WasmElementMode::declarative;
        else if (!active) segment.mode = WasmElementMode::passive;
        else segment.mode = WasmElementMode::active;
        if (active) {
            if (flags & 2u) {
                if (!r.uleb(segment.table_index)) {
                    reason = "truncated WebAssembly element segment table index";
                    return false;
                }
            }
            {
                std::uint8_t opcode = 0;
                if (!r.byte(opcode)) { reason = "truncated WebAssembly element offset expression"; return false; }
                segment.offset_expression_file_offset = {section_file_offset + r.position - 1};
                --r.position;
                auto expression = parse_integer_initializer(r, 0x7f, globals, section_file_offset,
                                                            instruction_work, stop);
                if (!expression) {
                    unsupported = expression.error().code == ErrorCode::unsupported;
                    reason = "invalid WebAssembly element offset expression: " + expression.error().message;
                    return false;
                }
                auto parsed = std::move(expression.value());
                if (!supported_extended_i32_offset(parsed)) {
                    unsupported = true;
                    reason = "WebAssembly element offset expression uses an opcode outside extended-const i32 add/sub/mul";
                    return false;
                }
                segment.evaluated_offset_value = parsed.evaluated_value_bits
                    ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(*parsed.evaluated_value_bits))
                    : std::nullopt;
                if (parsed.kind == WasmGlobalInitializerKind::numeric_constant) {
                    segment.offset_kind = WasmOffsetExpressionKind::i32_constant;
                    segment.offset_value = static_cast<std::uint32_t>(parsed.value);
                    segment.offset_instructions.push_back({0x41, parsed.value,
                        segment.offset_expression_file_offset});
                } else if (parsed.kind == WasmGlobalInitializerKind::global_get) {
                    segment.offset_kind = WasmOffsetExpressionKind::global_get;
                    segment.offset_value = static_cast<std::uint32_t>(parsed.value);
                    segment.offset_instructions.push_back({0x23, parsed.value,
                        segment.offset_expression_file_offset});
                } else {
                    segment.offset_kind = WasmOffsetExpressionKind::extended_integer;
                    segment.offset_instructions = std::move(parsed.instructions);
                }
            }
        }
        if (expressions && flags != 4) {
            std::uint8_t reference_type = 0;
            if (!r.byte(reference_type) || reference_type != 0x70) {
                unsupported = reference_type != 0x70;
                reason = "unsupported or malformed WebAssembly element reference type";
                return false;
            }
        } else if (!expressions && flags != 0) {
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
            if (!expressions) {
                if (!r.uleb(function_index)) {
                    reason = "truncated WebAssembly element function index";
                    return false;
                }
            } else {
                std::uint8_t opcode = 0;
                if (!r.byte(opcode)) {
                    reason = "truncated WebAssembly element initializer expression";
                    return false;
                }
                if (opcode == 0xd2) {
                    std::uint8_t end = 0;
                    if (!r.uleb(function_index) || !r.byte(end) || end != 0x0b) {
                        reason = "malformed WebAssembly ref.func element initializer";
                        return false;
                    }
                    segment.function_indices.push_back(function_index);
                } else if (opcode == 0xd0) {
                    std::int64_t heap_type = 0;
                    std::uint8_t end = 0;
                    if (!r.sleb(33, heap_type)) {
                        reason = "malformed WebAssembly ref.null heap type";
                        return false;
                    }
                    if (heap_type != -16) {
                        unsupported = true;
                        reason = "unsupported WebAssembly element ref.null heap type";
                        return false;
                    }
                    if (!r.byte(end) || end != 0x0b) {
                        reason = "malformed WebAssembly ref.null element initializer";
                        return false;
                    }
                    segment.function_indices.push_back(std::nullopt);
                } else {
                    unsupported = true;
                    reason = "unsupported WebAssembly element initializer expression";
                    return false;
                }
                continue;
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
            if (function_index && *function_index >= metadata.function_type_indices.size())
                return Error{ErrorCode::malformed, "WebAssembly element function index is outside the function index space"};
        }
        if (segment.mode != WasmElementMode::active) continue;
        if (segment.table_index >= table_count)
            return Error{ErrorCode::malformed, "WebAssembly active element segment references a missing table"};
        const auto offset = segment.offset_kind == WasmOffsetExpressionKind::i32_constant
            ? std::optional<std::uint32_t>(segment.offset_value) : segment.evaluated_offset_value;
        if (!offset) {
            unresolved_offset = true;
            continue;
        }
        const auto end = checked_add(*offset, segment.function_indices.size());
        if (!end || end.value() > metadata.initial_table_element_count) {
            out_of_bounds = true;
            continue;
        }
        for (std::size_t i = 0; i < segment.function_indices.size(); ++i) {
            const auto slot = *offset + static_cast<std::uint32_t>(i);
            if (segment.function_indices[i])
                slots[slot] = *segment.function_indices[i];
            else
                slots.erase(slot);
        }
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
        bool memory64 = false;
        if (!r.limits(true, limits, &memory64)) {
            if (memory64) { unsupported = true; reason = "memory64 definitions are unsupported by the wasm32 loader"; }
            else reason = "invalid memory limits";
            return false;
        }
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
        const auto offset = segment.offset_kind == WasmOffsetExpressionKind::i32_constant
            ? std::optional<std::uint32_t>(segment.offset_value) : segment.evaluated_offset_value;
        if (!offset) {
            diagnostics.push_back({DiagnosticSeverity::warning,
                "WebAssembly linear-memory view omitted because an active data segment offset expression remains unresolved", {}});
            return true;
        }
        const auto end = checked_add(*offset, segment.byte_count);
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
        const auto offset = segment.offset_kind == WasmOffsetExpressionKind::i32_constant
            ? segment.offset_value : *segment.evaluated_offset_value;
        const auto end = static_cast<std::uint64_t>(offset) + segment.byte_count;
        events.push_back({offset, index, true});
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
                  (begin - (metadata.data_segments[*active.rbegin()].offset_kind == WasmOffsetExpressionKind::i32_constant
                      ? metadata.data_segments[*active.rbegin()].offset_value
                      : *metadata.data_segments[*active.rbegin()].evaluated_offset_value))
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

Result<WasmGlobalInitializer> parse_integer_initializer(Reader &r, std::uint8_t expected,
    const std::vector<GlobalType> &globals,
    std::uint64_t section_file_offset, std::uint64_t &instruction_work, std::stop_token stop) {
    struct Value { std::uint8_t type; std::optional<std::uint64_t> bits; };
    std::vector<Value> stack;
    std::vector<WasmConstantInstruction> instructions;
    WasmGlobalInitializer initializer;
    initializer.expression_file_offset = {section_file_offset + r.position};
    for (;;) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled,"WebAssembly constant-expression parsing canceled"};
        WasmConstantInstruction instruction;
        instruction.file_offset = {section_file_offset + r.position};
        if (!r.byte(instruction.opcode)) return Error{ErrorCode::malformed,"unterminated integer global initializer"};
        const auto opcode = instruction.opcode;
        if (opcode == 0x0b) break;
        if (instructions.size() >= 256 || instruction_work >= 1'000'000)
            return Error{ErrorCode::resource_limit,"WebAssembly integer constant expressions exceed instruction limits"};
        ++instruction_work;
        std::uint8_t operator_input_type = 0, operator_result_type = 0;
        unsigned operator_arity = 0;
        if (opcode == 0x41 || opcode == 0x42) {
            std::int64_t literal = 0;
            if (!r.sleb(opcode == 0x41 ? 32 : 64, literal))
                return Error{ErrorCode::malformed,"invalid integer constant-expression literal"};
            instruction.immediate = opcode == 0x41 ? static_cast<std::uint32_t>(literal) : static_cast<std::uint64_t>(literal);
            stack.push_back({static_cast<std::uint8_t>(opcode == 0x41 ? 0x7f : 0x7e),instruction.immediate});
        } else if (opcode == 0x23) {
            std::uint32_t index = 0;
            // Extended constant expressions may read any earlier immutable
            // global. `globals` is built in module index order, so its current
            // extent also rejects forward and self references.
            if (!r.uleb(index) || index >= globals.size() || globals[index].mutable_value ||
                (globals[index].value != 0x7f && globals[index].value != 0x7e))
                return Error{ErrorCode::malformed,"integer constant expression must read an earlier immutable integer global"};
            instruction.immediate = index;
            stack.push_back({globals[index].value,{}});
        } else if (integer_constant_operator(opcode, operator_input_type, operator_result_type, operator_arity)) {
            if (stack.size() < operator_arity)
                return Error{ErrorCode::malformed,"integer constant-expression operator has stack underflow"};
            Value right_value{};
            if (operator_arity == 2) { right_value = stack.back(); stack.pop_back(); }
            if (stack.empty())
                return Error{ErrorCode::malformed,"integer constant-expression operator has stack underflow"};
            const auto left = stack.back(); stack.pop_back();
            if (left.type != operator_input_type || (operator_arity == 2 && right_value.type != operator_input_type))
                return Error{ErrorCode::malformed,"integer constant-expression operator has invalid operand types"};
            if (left.bits && (operator_arity == 1 || right_value.bits))
                stack.push_back({operator_result_type, apply_integer_constant_operator(opcode, *left.bits, right_value.bits)});
            else stack.push_back({operator_result_type, std::nullopt});
        } else if (opcode == 0x43 || opcode == 0x44 || opcode == 0xd0 || opcode == 0xd2) {
            return Error{ErrorCode::malformed,"integer global initializer has a non-integer operand"};
        } else return Error{ErrorCode::unsupported,"unsupported integer constant-expression opcode " + std::to_string(opcode)};
        instructions.push_back(instruction);
    }
    if (stack.size() != 1 || stack.back().type != expected)
        return Error{ErrorCode::malformed,"integer global initializer must leave exactly one value of its declared type"};
    initializer.evaluated_value_bits = stack.back().bits;
    if (instructions.size() == 1) {
        initializer.kind = instructions[0].opcode == 0x23 ? WasmGlobalInitializerKind::global_get : WasmGlobalInitializerKind::numeric_constant;
        initializer.value = instructions[0].immediate;
    } else {
        initializer.kind = WasmGlobalInitializerKind::extended_integer;
        initializer.instructions = std::move(instructions);
    }
    return initializer;
}

Result<bool> evaluate_numeric_initializers(WasmMetadata &metadata, std::stop_token stop) {
    const auto referenced_global_bits = [&](std::uint32_t index) -> std::optional<std::uint64_t> {
        if (index >= metadata.globals.size()) return std::nullopt;
        const auto &referenced = metadata.globals[index];
        if (referenced.imported) return referenced.host_value_bits;
        if (!referenced.initializer) return std::nullopt;
        return referenced.initializer->evaluated_value_bits;
    };
    for (auto &global : metadata.globals) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled,"WebAssembly constant-expression evaluation canceled"};
        if (!global.initializer || (global.value_type != 0x7f && global.value_type != 0x7e &&
                                    global.value_type != 0x7d && global.value_type != 0x7c)) continue;
        auto &initializer = *global.initializer;
        if (initializer.kind == WasmGlobalInitializerKind::global_get) {
            initializer.evaluated_value_bits = referenced_global_bits(static_cast<std::uint32_t>(initializer.value));
        } else if (initializer.kind == WasmGlobalInitializerKind::numeric_constant) {
            // The value field already retains the exact raw IEEE-754 bit
            // pattern for float constants; expose it through the same
            // resolved-value API used for integer constants.
            initializer.evaluated_value_bits = initializer.value;
        } else if (initializer.kind == WasmGlobalInitializerKind::extended_integer) {
            std::vector<std::optional<std::uint64_t>> stack;
            for (const auto &instruction : initializer.instructions) {
                const auto opcode = instruction.opcode;
                if (opcode == 0x41 || opcode == 0x42) stack.push_back(instruction.immediate);
                else if (opcode == 0x23) stack.push_back(referenced_global_bits(static_cast<std::uint32_t>(instruction.immediate)));
                else {
                    std::uint8_t input_type = 0, result_type = 0;
                    unsigned arity = 0;
                    // Parsing already validates this operator, stack shape and
                    // operand types; this pass only propagates exact raw bits.
                    if (!integer_constant_operator(opcode, input_type, result_type, arity))
                        return Error{ErrorCode::malformed,"retained integer constant expression has an invalid operator"};
                    std::optional<std::uint64_t> right;
                    if (arity == 2) { right = stack.back(); stack.pop_back(); }
                    const auto left = stack.back(); stack.pop_back();
                    if (left && (arity == 1 || right))
                        stack.push_back(apply_integer_constant_operator(opcode, *left, right));
                    else stack.push_back(std::nullopt);
                }
            }
            initializer.evaluated_value_bits = stack.back();
        }
    }
    return true;
}

Result<std::optional<std::uint32_t>> evaluate_i32_offset_expression(
    WasmOffsetExpressionKind kind, std::uint32_t value,
    const std::vector<WasmConstantInstruction> &instructions,
    const WasmMetadata &metadata, std::stop_token stop) {
    if (kind == WasmOffsetExpressionKind::i32_constant) return std::optional<std::uint32_t>(value);
    const auto global_bits = [&](std::uint32_t index) -> std::optional<std::uint64_t> {
        if (index >= metadata.globals.size()) return std::nullopt;
        const auto &global = metadata.globals[index];
        if (global.imported) return global.host_value_bits;
        if (!global.initializer) return std::nullopt;
        return global.initializer->evaluated_value_bits;
    };
    if (kind == WasmOffsetExpressionKind::global_get) {
        const auto bits = global_bits(value);
        if (!bits) return std::optional<std::uint32_t>{};
        return std::optional<std::uint32_t>(static_cast<std::uint32_t>(*bits));
    }
    std::vector<std::optional<std::uint64_t>> stack;
    stack.reserve(256);
    for (const auto &instruction : instructions) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly offset-expression evaluation canceled"};
        const auto opcode = instruction.opcode;
        if (opcode == 0x41 || opcode == 0x42) stack.push_back(instruction.immediate);
        else if (opcode == 0x23) stack.push_back(global_bits(static_cast<std::uint32_t>(instruction.immediate)));
        else {
            std::uint8_t input_type = 0, result_type = 0;
            unsigned arity = 0;
            if (!integer_constant_operator(opcode, input_type, result_type, arity) || stack.size() < arity)
                return Error{ErrorCode::malformed, "Retained WebAssembly offset expression is invalid"};
            std::optional<std::uint64_t> right;
            if (arity == 2) { right = stack.back(); stack.pop_back(); }
            const auto left = stack.back(); stack.pop_back();
            if (left && (arity == 1 || right))
                stack.push_back(apply_integer_constant_operator(opcode, *left, right));
            else stack.push_back(std::nullopt);
        }
    }
    if (stack.size() != 1)
        return Error{ErrorCode::malformed, "Retained WebAssembly offset expression has an invalid result stack"};
    if (!stack.back()) return std::optional<std::uint32_t>{};
    return std::optional<std::uint32_t>(static_cast<std::uint32_t>(*stack.back()));
}

Result<bool> evaluate_segment_offsets(WasmMetadata &metadata, std::stop_token stop) {
    for (auto &segment : metadata.data_segments) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly data offset evaluation canceled"};
        if (segment.mode != WasmDataMode::active) continue;
        auto offset = evaluate_i32_offset_expression(segment.offset_kind, segment.offset_value,
            segment.offset_instructions, metadata, stop);
        if (!offset) return offset.error();
        segment.evaluated_offset_value = offset.value();
    }
    for (auto &segment : metadata.element_segments) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly element offset evaluation canceled"};
        if (segment.mode != WasmElementMode::active) continue;
        auto offset = evaluate_i32_offset_expression(segment.offset_kind, segment.offset_value,
            segment.offset_instructions, metadata, stop);
        if (!offset) return offset.error();
        segment.evaluated_offset_value = offset.value();
    }
    return true;
}

Result<bool> parse_globals(Reader &r, std::uint32_t &count, std::uint32_t imported_count,
                   std::vector<GlobalType> &globals,
                   WasmMetadata &metadata, std::uint64_t section_file_offset,
                   std::uint64_t &instruction_work, std::string &reason, bool &unsupported,
                   std::stop_token stop) {
    if (!r.uleb(count) || count > max_vector_items - imported_count) { reason = "invalid global vector count"; return false; }
    for (std::uint32_t i = 0; i < count; ++i) {
        WasmGlobal entry;
        entry.section_file_offset = {section_file_offset};
        entry.entry_file_offset = {section_file_offset + r.position};
        std::uint8_t mutability = 0;
        std::uint8_t type = 0;
        if (!r.value_type(&type) || !r.byte(mutability) || mutability > 1) { reason = "invalid global type"; return false; }
        WasmGlobalInitializer initializer;
        initializer.expression_file_offset = {section_file_offset + r.position};
        if (type == 0x7f || type == 0x7e) {
            auto parsed = parse_integer_initializer(r,type,globals,section_file_offset,instruction_work,stop);
            if (!parsed) return parsed.error();
            initializer = std::move(parsed.value());
        } else {
            std::uint8_t opcode = 0, end = 0;
            if (!r.byte(opcode)) { reason = "truncated global initializer"; return false; }
            if ((opcode == 0x43 && type == 0x7d) || (opcode == 0x44 && type == 0x7c)) {
                const unsigned width = opcode == 0x43 ? 4 : 8;
                for (unsigned byte_index = 0; byte_index < width; ++byte_index) {
                    std::uint8_t byte = 0;
                    if (!r.byte(byte)) { reason = "truncated floating-point global initializer"; return false; }
                    initializer.value |= static_cast<std::uint64_t>(byte) << (byte_index * 8);
                }
            } else if (opcode == 0x23) {
                std::uint32_t index = 0;
                if (!r.uleb(index) || index >= globals.size() ||
                    globals[index].mutable_value || globals[index].value != type) {
                    reason = "global initializer must read an earlier immutable global of matching type";
                    return false;
                }
                initializer.kind = WasmGlobalInitializerKind::global_get;
                initializer.value = index;
            } else if (opcode == 0xd0 && (type == 0x70 || type == 0x6f)) {
                std::int64_t heap_type = 0;
                if (!r.sleb(33, heap_type)) { reason = "invalid ref.null global initializer heap type"; return false; }
                if ((type == 0x70 && heap_type != -16) || (type == 0x6f && heap_type != -17)) {
                    unsupported = true; reason = "ref.null global initializer heap type does not match its reference type"; return false;
                }
                initializer.kind = WasmGlobalInitializerKind::ref_null;
            } else if (opcode == 0xd2 && type == 0x70) {
                std::uint32_t index = 0;
                if (!r.uleb(index)) { reason = "invalid ref.func global initializer index"; return false; }
                initializer.kind = WasmGlobalInitializerKind::ref_func;
                initializer.value = index; // Resolved after the full function index space is available.
            } else if (opcode == 0x41 || opcode == 0x42 || opcode == 0x43 || opcode == 0x44 ||
                       opcode == 0xd0 || opcode == 0xd2) {
                reason = "global initializer type mismatch"; return false;
            } else {
                unsupported = true; reason = "unsupported WebAssembly global initializer opcode " + std::to_string(opcode); return false;
            }
            if (!r.byte(end) || end != 0x0b) { reason = "global initializer must contain one expression and end"; return false; }
        }
        globals.push_back({type, mutability != 0});
        entry.value_type = type;
        entry.mutable_value = mutability != 0;
        entry.initializer = std::move(initializer);
        metadata.globals.push_back(std::move(entry));
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
                   std::span<const std::uint8_t> declared_function_references,
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
            if (!code.uleb(count) || count > 12) { unsupported = true; return fail("branch table exceeds the maximum case count for a 15-byte instruction"); }
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
        } else if (op == 0x1c) {
            std::uint32_t count = 0;
            std::uint8_t type = 0;
            if (!code.uleb(count) || count != 1 || !code.value_type(&type))
                return fail("typed select requires exactly one supported result type");
            if (!pop(0x7f) || !pop(type) || !pop(type) || !push(type))
                return fail("typed select condition or value type mismatch");
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
        } else if (op == 0xfd) {
            std::uint32_t subopcode = 0;
            if (!code.uleb(subopcode)) return fail("invalid SIMD subopcode");
            if (wasm_simd_integer_binary_op(subopcode)) {
                if (!pop(0x7b) || !pop(0x7b) || !push(0x7b))
                    return fail("SIMD integer arithmetic requires two v128 operands");
                continue;
            }
            const bool shift = (subopcode >= 0x6b && subopcode <= 0x6d) ||
                (subopcode >= 0x8b && subopcode <= 0x8d) ||
                (subopcode >= 0xab && subopcode <= 0xad) ||
                (subopcode >= 0xcb && subopcode <= 0xcd);
            if (!shift) {
                unsupported = true;
                return fail("SIMD opcode is outside the validated integer arithmetic/shift subset");
            }
            if (!pop(0x7f) || !pop(0x7b) || !push(0x7b))
                return fail("SIMD shift requires a v128 value and i32 lane count");
        } else if (op == 0xfc) {
            std::uint32_t subopcode = 0, first = 0, second = 0;
            if (!code.uleb(subopcode)) return fail("invalid bulk-memory subopcode");
            const auto memory_count = metadata.imported_memories + metadata.defined_memories;
            if (subopcode <= 7) {
                static constexpr std::array<std::uint8_t, 8> inputs{
                    0x7d, 0x7d, 0x7c, 0x7c, 0x7d, 0x7d, 0x7c, 0x7c};
                static constexpr std::array<std::uint8_t, 8> outputs{
                    0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7e, 0x7e};
                if (!pop(inputs[subopcode]) || !push(outputs[subopcode]))
                    return fail("trunc_sat operand type mismatch");
            } else if (subopcode == 8) {
                if (!code.uleb(first) || !code.uleb(second)) return fail("truncated memory.init immediates");
                if (!metadata.declared_data_count || first >= *metadata.declared_data_count ||
                    memory_count != 1 || second != 0)
                    return fail("memory.init requires a declared data segment and memory index zero");
                if (!pop(0x7f) || !pop(0x7f) || !pop(0x7f))
                    return fail("memory.init requires destination, source, and length i32 operands");
            } else if (subopcode == 9) {
                if (!code.uleb(first)) return fail("truncated data.drop segment index");
                if (!metadata.declared_data_count || first >= *metadata.declared_data_count)
                    return fail("data.drop segment index is out of range or data-count is missing");
            } else if (subopcode == 10) {
                if (!code.uleb(first) || !code.uleb(second)) return fail("truncated memory.copy immediates");
                if (memory_count != 1 || first != 0 || second != 0)
                    return fail("memory.copy requires one memory and both indices zero");
                if (!pop(0x7f) || !pop(0x7f) || !pop(0x7f))
                    return fail("memory.copy requires destination, source, and length i32 operands");
            } else if (subopcode == 11) {
                if (!code.uleb(first)) return fail("truncated memory.fill memory index");
                if (memory_count != 1 || first != 0)
                    return fail("memory.fill requires one memory and index zero");
                if (!pop(0x7f) || !pop(0x7f) || !pop(0x7f))
                    return fail("memory.fill requires destination, byte value, and length i32 operands");
            } else if (subopcode == 12) {
                if (!code.uleb(first) || !code.uleb(second)) return fail("truncated table.init immediates");
                const auto table_count = metadata.imported_tables + metadata.defined_tables;
                if (first >= metadata.element_segments.size() || table_count != 1 || second != 0)
                    return fail("table.init requires a valid element segment and table index zero");
                if (!pop(0x7f) || !pop(0x7f) || !pop(0x7f))
                    return fail("table.init requires destination, source, and length i32 operands");
            } else if (subopcode == 13) {
                if (!code.uleb(first) || first >= metadata.element_segments.size())
                    return fail("elem.drop segment index is out of range");
            } else if (subopcode == 14) {
                if (!code.uleb(first) || !code.uleb(second)) return fail("truncated table.copy immediates");
                const auto table_count = metadata.imported_tables + metadata.defined_tables;
                if (table_count != 1 || first != 0 || second != 0)
                    return fail("table.copy requires one table and both indices zero");
                if (!pop(0x7f) || !pop(0x7f) || !pop(0x7f))
                    return fail("table.copy requires destination, source, and length i32 operands");
            } else if (subopcode == 15) {
                if (!code.uleb(first)) return fail("truncated table.grow table index");
                if (metadata.imported_tables + metadata.defined_tables != 1 || first != 0)
                    return fail("table.grow requires one table at index zero");
                if (!pop(0x7f) || !pop(0x70) || !push(0x7f))
                    return fail("table.grow requires a funcref and i32 delta, and returns i32");
            } else if (subopcode == 16) {
                if (!code.uleb(first)) return fail("truncated table.size table index");
                if (metadata.imported_tables + metadata.defined_tables != 1 || first != 0)
                    return fail("table.size requires one table at index zero");
                if (!push(0x7f)) return fail("operand stack limit exceeded");
            } else if (subopcode == 17) {
                if (!code.uleb(first)) return fail("truncated table.fill table index");
                if (metadata.imported_tables + metadata.defined_tables != 1 || first != 0)
                    return fail("table.fill requires one table at index zero");
                if (!pop(0x7f) || !pop(0x70) || !pop(0x7f))
                    return fail("table.fill requires destination i32, funcref value, and length i32 operands");
            } else {
                unsupported = true;
                return fail("0xfc subopcode is outside the enabled scalar-conversion, bulk-memory, and table-operation subset");
            }
        } else if (op >= 0xd0 && op <= 0xd2) {
            if (op == 0xd0) {
                std::int64_t heap_type = 0;
                if (!code.sleb(33, heap_type)) return fail("invalid ref.null heap type");
                const auto reference_type = heap_type == -16 ? std::uint8_t{0x70} :
                                            heap_type == -17 ? std::uint8_t{0x6f} : std::uint8_t{0};
                if (!reference_type) return fail("ref.null supports only funcref and externref");
                if (!push(reference_type)) return fail("operand stack limit exceeded");
            } else if (op == 0xd1) {
                const auto reference_type = pop_any();
                if ((reference_type && reference_type != 0x70 && reference_type != 0x6f) || !push(0x7f))
                    return fail("ref.is_null requires a reference operand");
            } else {
                if (!code.uleb(index) || index >= metadata.function_type_indices.size()) return fail("ref.func function index out of range");
                if (!declared_function_references[index]) return fail("ref.func function is not declared outside a function body");
                if (!push(0x70)) return fail("operand stack limit exceeded");
            }
        } else if (op >= 0xc0 && op <= 0xc4) {
            const std::uint8_t type = op <= 0xc1 ? std::uint8_t{0x7f} : std::uint8_t{0x7e};
            if (!pop(type) || !push(type)) return fail("sign-extension operand type mismatch");
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

Result<LoadedImage> load_wasm(std::shared_ptr<const ByteStorage> storage, std::stop_token stop,
                              WasmGlobalImportResolver global_resolver,
                              WasmTableMemoryImportResolver table_memory_resolver,
                              WasmFunctionImportResolver function_resolver) {
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
    std::uint64_t constant_instruction_work = 0;
    WasmMetadata wasm;
    std::vector<Diagnostic> wasm_diagnostics;
    std::uint64_t name_bytes = 0;
    std::uint32_t type_count = 0;
    std::string parse_reason;
    bool unsupported_payload = false;
    std::array<bool, 13> seen{};
    std::array<bool, 13> warned_section{};
    std::vector<std::uint8_t> section_ids;
    std::vector<std::uint32_t> section_sizes;
    bool warned_custom = false;
    bool saw_producers = false;
    bool saw_target_features = false;
    bool saw_linking = false;
    bool linking_metadata_valid = false;
    bool saw_dylink = false;
    std::size_t relocation_entry_count = 0;
    int previous_order = 0;
    Reader module{bytes, 8};
    while (module.position < bytes.size()) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly loading canceled"};
        const auto section_id_offset = module.position;
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
        section_ids.push_back(id);
        section_sizes.push_back(section_size);
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
                    WasmGlobal global;
                    global.value_type = *entry.global_value_type;
                    global.mutable_value = entry.global_mutable;
                    global.imported = true;
                    global.section_file_offset = entry.section_file_offset;
                    global.entry_file_offset = entry.entry_file_offset;
                    wasm.globals.push_back(std::move(global));
                }
        }
        else if (id == 3) valid = parse_functions(section, type_count, function_types);
        else if (id == 4) valid = parse_tables(section, wasm.defined_tables, wasm, parse_reason, unsupported_payload);
        else if (id == 5) valid = parse_memories(section, wasm.defined_memories, wasm, parse_reason, unsupported_payload);
        else if (id == 6) {
            auto parsed = parse_globals(section, wasm.defined_globals, wasm.imported_globals, globals, wasm, section_begin,
                                        constant_instruction_work, parse_reason, unsupported_payload,stop);
            if (!parsed) return parsed.error();
            valid = parsed.value();
        }
        else if (id == 7) valid = parse_exports(section, wasm, section_begin, name_bytes, parse_reason, unsupported_payload);
        else if (id == 8) valid = parse_start(section, wasm, section_begin, parse_reason);
        else if (id == 9) valid = parse_elements(section, wasm, section_begin, globals,
            constant_instruction_work, stop, parse_reason, unsupported_payload);
        else if (id == 11) valid = parse_data(section, wasm, section_begin, globals,
            constant_instruction_work, stop, parse_reason, unsupported_payload);
        else if (id == 12) valid = parse_data_count(section, wasm, parse_reason);
        else if (id == 10) valid = parse_code(section, wasm.imported_functions, bodies, section_begin);
        else if (id == 0) {
            std::string custom_name;
            valid = section.name(custom_name, name_bytes);
            if (valid) {
                if (wasm.custom_sections.size() >= max_wasm_custom_sections)
                    return Error{ErrorCode::resource_limit, "WebAssembly custom-section count exceeds the 65536-row limit"};
                WasmCustomSection row;
                row.name = custom_name;
                row.section_file_offset = {section_id_offset};
                row.section_size = section_size;
                row.payload_file_offset = {section_begin + section.position};
                row.payload_size = static_cast<std::uint32_t>(section.bytes.size() - section.position);
                wasm.custom_sections.push_back(std::move(row));
            }
            if (valid && custom_name == "name") {
                valid = parse_name_section(section, section_begin, wasm, name_bytes, parse_reason);
            } else if (valid && custom_name == "producers") {
                if (saw_producers) {
                    wasm_diagnostics.push_back({DiagnosticSeverity::info,
                        "Additional WebAssembly producers custom section was ignored", {}});
                } else {
                    saw_producers = true;
                    std::vector<WasmProducer> producers;
                    std::string producers_reason;
                    if (parse_producers(section, section_begin, name_bytes, producers, producers_reason)) {
                        wasm.producers = std::move(producers);
                    } else {
                        wasm_diagnostics.push_back({DiagnosticSeverity::info,
                            "Malformed WebAssembly producers custom section was ignored: " + producers_reason, {}});
                    }
                }
            } else if (valid && custom_name == "target_features") {
                if (saw_target_features) {
                    wasm_diagnostics.push_back({DiagnosticSeverity::info,
                        "Additional WebAssembly target_features custom section was ignored", {}});
                } else {
                    saw_target_features = true;
                    std::vector<WasmTargetFeature> features;
                    std::string feature_reason;
                    if (parse_target_features(section, section_begin, name_bytes, features, feature_reason)) {
                        wasm.target_features = std::move(features);
                    } else {
                        wasm_diagnostics.push_back({DiagnosticSeverity::info,
                            "Malformed WebAssembly target_features custom section was ignored: " + feature_reason, {}});
                    }
                }
            } else if (valid && custom_name == "dylink.0") {
                if (saw_dylink) {
                    wasm_diagnostics.push_back({DiagnosticSeverity::info,
                        "Additional WebAssembly dylink.0 custom section was ignored", {}});
                } else {
                    saw_dylink = true;
                    WasmDylinkInfo dylink;
                    std::string dylink_reason;
                    if (parse_dylink_info(section, section_begin, name_bytes, dylink, dylink_reason)) {
                        wasm.dylink = std::move(dylink);
                    } else {
                        wasm_diagnostics.push_back({DiagnosticSeverity::info,
                            "Malformed WebAssembly dylink.0 custom section was ignored: " + dylink_reason, {}});
                    }
                }
            } else if (valid && custom_name == "linking") {
                if (saw_linking) {
                    wasm_diagnostics.push_back({DiagnosticSeverity::info,
                        "Additional WebAssembly linking custom section was ignored", {}});
                } else {
                    saw_linking = true;
                    std::vector<WasmLinkingSegmentInfo> segments;
                    std::vector<WasmLinkingSymbol> symbols;
                    bool segment_info_present = false;
                    bool symbol_table_present = false;
                    std::string linking_reason;
                    if (parse_linking_segment_info(section, section_begin, name_bytes, wasm,
                                                   static_cast<std::uint32_t>(function_types.size()),
                                                   segments, symbols, segment_info_present,
                                                   symbol_table_present, linking_reason)) {
                        wasm.linking_segments = std::move(segments);
                        wasm.linking_segment_info_present = segment_info_present;
                        wasm.linking_symbols = std::move(symbols);
                        wasm.linking_symbol_table_present = symbol_table_present;
                        linking_metadata_valid = true;
                    } else {
                        wasm_diagnostics.push_back({DiagnosticSeverity::info,
                            "Malformed or unsupported WebAssembly linking custom section was ignored: " + linking_reason, {}});
                    }
                }
            } else if (valid && custom_name.starts_with("reloc.")) {
                WasmRelocationSection relocation;
                std::string relocation_reason;
                const auto remaining = static_cast<std::size_t>(max_wasm_linking_symbols) - relocation_entry_count;
                if (parse_relocation_section(section, section_begin, custom_name, section_ids, section_sizes,
                                             wasm, linking_metadata_valid, remaining, stop, relocation, relocation_reason)) {
                    relocation_entry_count += relocation.entries.size();
                    wasm.relocation_sections.push_back(std::move(relocation));
                } else if (stop.stop_requested()) {
                    return Error{ErrorCode::canceled, "WebAssembly relocation parsing canceled"};
                } else {
                    wasm_diagnostics.push_back({DiagnosticSeverity::info,
                        "Malformed or unsupported WebAssembly relocation section was ignored: " + relocation_reason, {}});
                }
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
    if (wasm.linking_segment_info_present && wasm.linking_segments.size() != wasm.data_segments.size()) {
        wasm_diagnostics.push_back({DiagnosticSeverity::info,
            "WebAssembly linking segment-info count does not match the data section; segment metadata was ignored", {}});
        wasm.linking_segments.clear();
        wasm.linking_segment_info_present = false;
    }
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
    const auto valid_offset_global = [&](std::uint64_t index) {
        return index < globals.size() &&
               globals[static_cast<std::size_t>(index)].value == 0x7f &&
               !globals[static_cast<std::size_t>(index)].mutable_value;
    };
    for (const auto &segment : wasm.data_segments) {
        if (segment.mode == WasmDataMode::active &&
            segment.memory_index >= static_cast<std::uint64_t>(wasm.imported_memories) + wasm.defined_memories)
            return Error{ErrorCode::malformed, "WebAssembly active data segment references a missing memory"};
        if (segment.mode == WasmDataMode::active && segment.offset_kind == WasmOffsetExpressionKind::global_get &&
            !valid_offset_global(segment.offset_value))
            return Error{ErrorCode::malformed, "WebAssembly data segment offset global must be an earlier immutable i32 global"};
    }
    for (const auto &segment : wasm.element_segments) {
        if (segment.mode == WasmElementMode::active && segment.offset_kind == WasmOffsetExpressionKind::global_get &&
            !valid_offset_global(segment.offset_value))
            return Error{ErrorCode::malformed, "WebAssembly element segment offset global must be an earlier immutable i32 global"};
    }
    if (static_cast<std::uint64_t>(wasm.imported_tables) + wasm.defined_tables > 1)
        return Error{ErrorCode::unsupported, "Multiple WebAssembly tables require an extension outside this loader's subset"};
    wasm.type_count = type_count;
    wasm.defined_functions = static_cast<std::uint32_t>(function_types.size());
    wasm.function_type_indices.insert(wasm.function_type_indices.end(), function_types.begin(), function_types.end());
    for (const auto &name : wasm.index_names) {
        std::uint64_t index_space_size = 0;
        switch (name.subsection_id) {
        case 4: index_space_size = wasm.type_count; break;
        case 5: index_space_size = static_cast<std::uint64_t>(wasm.imported_tables) + wasm.defined_tables; break;
        case 6: index_space_size = static_cast<std::uint64_t>(wasm.imported_memories) + wasm.defined_memories; break;
        case 7: index_space_size = wasm.globals.size(); break;
        case 8: index_space_size = wasm.element_segments.size(); break;
        case 9: index_space_size = wasm.data_segments.size(); break;
        default: return Error{ErrorCode::malformed, "WebAssembly indexed-name metadata has an invalid subsection id"};
        }
        if (name.index >= index_space_size)
            return Error{ErrorCode::malformed, "WebAssembly name index is outside its corresponding module index space"};
    }
    // Module-environment ref.func expressions declare their targets, including
    // global initializers. Resolve once so body validation has bounded O(1)
    // declaration lookups rather than rescanning every external descriptor.
    std::vector<std::uint8_t> declared_function_references(wasm.function_type_indices.size());
    for (const auto &entry : wasm.exports)
        if (entry.kind == WasmExternalKind::function && entry.index < declared_function_references.size())
            declared_function_references[entry.index] = 1;
    for (const auto &segment : wasm.element_segments)
        for (const auto &index : segment.function_indices)
            if (index && *index < declared_function_references.size()) declared_function_references[*index] = 1;
    for (std::size_t index = 0; index < wasm.globals.size(); ++index) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly global initializer validation canceled"};
        const auto &initializer = wasm.globals[index].initializer;
        if (!initializer || initializer->kind != WasmGlobalInitializerKind::ref_func) continue;
        if (initializer->value >= declared_function_references.size())
            return Error{ErrorCode::malformed, "WebAssembly global[" + std::to_string(index) +
                "] ref.func initializer index is outside the function index space"};
        declared_function_references[static_cast<std::size_t>(initializer->value)] = 1;
    }
    std::size_t retained_local_types = 0;
    wasm.function_locals.reserve(bodies.size());
    for (const auto &body : bodies) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly body validation canceled"};
        parse_reason.clear(); unsupported_payload = false;
        bool canceled = false, limited = false;
        if (!validate_body(body, bytes, wasm, globals, declared_function_references, stop, parse_reason,
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
    for (auto &entry : wasm.imports) {
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
    const auto limits_compatible = [](const WasmLimits &required, const WasmLimits &provided) {
        if (required.shared != provided.shared || provided.minimum < required.minimum) return false;
        if (required.maximum && (!provided.maximum || *provided.maximum > *required.maximum)) return false;
        return true;
    };
    if (function_resolver) {
        try {
            for (auto &entry : wasm.imports) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly function import resolution canceled"};
                if (entry.kind != WasmExternalKind::function) continue;
                auto binding = function_resolver(entry);
                if (!binding) continue;
                if (binding->symbol.empty() || binding->symbol.size() > 4096)
                    return Error{ErrorCode::invalid_argument, "WebAssembly host function binding symbol must contain 1 to 4096 bytes"};
                if (!entry.function_type_index || *entry.function_type_index >= wasm.function_types.size())
                    return Error{ErrorCode::malformed, "WebAssembly function import lacks a valid module signature"};
                if (!(binding->type == wasm.function_types[*entry.function_type_index]))
                    return Error{ErrorCode::invalid_argument, "WebAssembly host function binding '" + binding->symbol + "' has an incompatible signature for import '" + entry.module + "." + entry.name + "'"};
                entry.host_binding = std::move(binding->symbol);
                entry.resolution_status = WasmImportResolutionStatus::symbolic_host_binding;
            }
        } catch (...) {
            return Error{ErrorCode::invalid_argument, "WebAssembly function import resolver threw an exception"};
        }
    }
    for (auto &entry : wasm.imports) {
        if (entry.kind != WasmExternalKind::table && entry.kind != WasmExternalKind::memory) continue;
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly table/memory import resolution canceled"};
        const auto kind = entry.kind == WasmExternalKind::table ? "table" : "memory";
        const auto import_name = entry.module + "." + entry.name;
        if (!table_memory_resolver) {
            wasm_diagnostics.push_back({DiagnosticSeverity::info,
                std::string("WebAssembly ") + kind + " import '" + import_name + "' remains unresolved: no host facts supplied", {}});
            continue;
        }
        std::optional<WasmImportHostFacts> facts;
        try { facts = table_memory_resolver(entry); }
        catch (...) { return Error{ErrorCode::invalid_argument, "WebAssembly table/memory import resolver threw an exception"}; }
        if (!facts) {
            wasm_diagnostics.push_back({DiagnosticSeverity::info,
                std::string("WebAssembly ") + kind + " import '" + import_name + "' remains unresolved: resolver returned no host facts", {}});
            continue;
        }
        if (!entry.limits || !facts->limits)
            return Error{ErrorCode::invalid_argument, std::string("WebAssembly host ") + kind + " facts must include limits"};
        if (entry.kind == WasmExternalKind::table) {
            if (facts->memory64)
                return Error{ErrorCode::invalid_argument, "WebAssembly host table facts cannot declare memory64"};
            if (!facts->table_reference_type)
                return Error{ErrorCode::invalid_argument, "WebAssembly host table facts must include a reference type"};
            if (*facts->table_reference_type != 0x70)
                return Error{ErrorCode::invalid_argument, "WebAssembly host table reference type does not match the module's funcref import"};
        } else {
            if (facts->table_reference_type)
                return Error{ErrorCode::invalid_argument, "WebAssembly host memory facts cannot declare a table reference type"};
            if (facts->memory64)
                return Error{ErrorCode::unsupported, "WebAssembly memory64 host imports are unsupported by the wasm32 loader"};
            if (facts->limits->minimum > 65536 || (facts->limits->maximum && *facts->limits->maximum > 65536))
                return Error{ErrorCode::invalid_argument, "WebAssembly host memory limits exceed the wasm32 65,536-page maximum"};
        }
        if (facts->limits->maximum && *facts->limits->maximum < facts->limits->minimum)
            return Error{ErrorCode::invalid_argument, std::string("WebAssembly host ") + kind + " maximum is below its minimum"};
        if (!limits_compatible(*entry.limits, *facts->limits))
            return Error{ErrorCode::invalid_argument, std::string("WebAssembly host ") + kind + " import '" + import_name + "' is incompatible with the module's limits"};
        if (!facts->binding.empty()) {
            if (facts->binding.size() > 4096)
                return Error{ErrorCode::invalid_argument, "WebAssembly host object binding must not exceed 4096 bytes"};
            entry.host_binding = facts->binding;
        }
        entry.resolution_status = facts->binding.empty()
            ? WasmImportResolutionStatus::compatible_host_facts
            : WasmImportResolutionStatus::symbolic_host_binding;
        wasm_diagnostics.push_back({DiagnosticSeverity::info,
            std::string("WebAssembly ") + kind + " import '" + import_name + "' has compatible host type and limits; runtime binding remains external", {}});
    }
    if (global_resolver) {
        try {
            for (auto &entry : wasm.imports) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "WebAssembly import resolution canceled"};
                if (entry.kind != WasmExternalKind::global || entry.index >= wasm.globals.size()) continue;
                auto value = global_resolver(entry);
                if (!value) continue;
                const auto type = *entry.global_value_type;
                if ((type == 0x7f || type == 0x7d) && (*value >> 32) != 0)
                    return Error{ErrorCode::invalid_argument, "WebAssembly host global value exceeds its 32-bit type width"};
                if (type == 0x70)
                    return Error{ErrorCode::unsupported, "WebAssembly host funcref global resolution is unsupported"};
                if (type != 0x7f && type != 0x7e && type != 0x7d && type != 0x7c)
                    return Error{ErrorCode::unsupported, "WebAssembly host global resolution supports only numeric value types"};
                wasm.globals[entry.index].host_value_bits = *value;
                entry.resolution_status = WasmImportResolutionStatus::supplied_global_value;
            }
        } catch (...) {
            return Error{ErrorCode::invalid_argument, "WebAssembly global import resolver threw an exception"};
        }
    }
    auto evaluated_initializers = evaluate_numeric_initializers(wasm,stop);
    if (!evaluated_initializers) return evaluated_initializers.error();
    auto evaluated_offsets = evaluate_segment_offsets(wasm, stop);
    if (!evaluated_offsets) return evaluated_offsets.error();
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
    for (const auto &name : wasm.label_names) {
        if (name.function_index >= wasm.function_type_indices.size())
            return Error{ErrorCode::malformed, "WebAssembly label name function index is outside the function index space"};
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
        "Function bodies are MVP type-validated and mapped to function-relative address spaces; host function binding and runtime table/memory instantiation remain external", {}});
    loaded.diagnostics.insert(loaded.diagnostics.end(), wasm_diagnostics.begin(), wasm_diagnostics.end());
    auto read = loaded.metadata_reads.include({0}, bytes.size());
    if (!read) return read.error();
    loaded.metadata_reads_complete = true;
    return loaded;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate WebAssembly parser state"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "WebAssembly parser state exceeds container limits"};
    }
}
} // namespace hexlab
