#include "hexlab/decompiler/wasm_lifting.hpp"

#include "hexlab/processors/wasm_simd_integer.hpp"
#include <algorithm>
#include <array>
#include <deque>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <vector>
#include <iterator>

namespace hexlab::decompiler {
namespace {
using Stack = std::vector<ExpressionPtr>;
enum class ReferenceNullness : std::uint8_t { unknown, null_value, non_null };

ValueType integer(unsigned bits, bool sign = false) { return {TypeKind::integer, static_cast<std::uint16_t>(bits), sign}; }
ValueType floating(unsigned bits) { return {TypeKind::floating, static_cast<std::uint16_t>(bits), false}; }
ValueType vector(unsigned bits, TypeKind element = TypeKind::unknown, unsigned element_bits = 0,
                 unsigned lanes = 0, bool sign = false) {
    return {TypeKind::vector, static_cast<std::uint16_t>(bits), sign, element,
            static_cast<std::uint16_t>(element_bits), static_cast<std::uint8_t>(lanes)};
}
ValueType funcref() { return {TypeKind::pointer, 32, false}; }
std::optional<ValueType> wasm_value_type(std::uint8_t code) {
    switch (code) {
    case 0x7f: return integer(32);
    case 0x7e: return integer(64);
    case 0x7d: return floating(32);
    case 0x7c: return floating(64);
    case 0x70: return funcref();
    // The common IR keeps both Wasm reference classes as opaque pointer-sized
    // values; the module validator still checks their distinct Wasm types.
    case 0x6f: return funcref();
    default: return {};
    }
}
ExpressionPtr constant(std::uint64_t value, ValueType type) {
    return std::make_shared<Expression>(Expression{type, ConstantValue{value, type}});
}
ExpressionPtr unary(std::string op, ExpressionPtr value, ValueType type) {
    return std::make_shared<Expression>(Expression{type, UnaryValue{std::move(op), std::move(value)}});
}
ExpressionPtr binary(std::string op, ExpressionPtr left, ExpressionPtr right, ValueType type) {
    return std::make_shared<Expression>(Expression{type, BinaryValue{std::move(op), std::move(left), std::move(right)}});
}
ReferenceNullness expression_nullness(const ExpressionPtr &expression, unsigned depth = 0) {
    if (!expression || depth >= 64 || expression->type.kind != TypeKind::pointer)
        return ReferenceNullness::unknown;
    if (const auto *literal = std::get_if<ConstantValue>(&expression->value))
        return literal->value == 0 ? ReferenceNullness::null_value : ReferenceNullness::non_null;
    if (const auto *reference = std::get_if<UnaryValue>(&expression->value);
        reference && reference->operation.rfind("wasm_ref_func_", 0) == 0)
        return ReferenceNullness::non_null;
    const auto *selection = std::get_if<BinaryValue>(&expression->value);
    if (!selection || selection->operation != "select_if") return ReferenceNullness::unknown;
    const auto *condition = selection->left
        ? std::get_if<ConstantValue>(&selection->left->value) : nullptr;
    const auto *alternatives = selection->right
        ? std::get_if<BinaryValue>(&selection->right->value) : nullptr;
    if (!alternatives || alternatives->operation != "pair") return ReferenceNullness::unknown;
    if (condition && condition->type.kind == TypeKind::integer)
        return expression_nullness(condition->value != 0 ? alternatives->left : alternatives->right, depth + 1);
    const auto when_true = expression_nullness(alternatives->left, depth + 1);
    const auto when_false = expression_nullness(alternatives->right, depth + 1);
    return when_true == when_false ? when_true : ReferenceNullness::unknown;
}
std::optional<std::uint64_t> immediate(const Instruction &i, std::size_t n = 0) {
    if (n >= i.operands.size()) return {};
    if (const auto *v = std::get_if<ImmediateOperand>(&i.operands[n])) return v->value;
    return {};
}
std::optional<std::uint8_t> bulk_memory_subopcode(const Instruction &i) {
    if (i.length < 2 || std::to_integer<std::uint8_t>(i.bytes[0]) != 0xfc) return {};
    std::uint32_t subopcode = 0;
    for (std::size_t position = 1; position < i.length && position < i.bytes.size() && position <= 5; ++position) {
        const auto byte = std::to_integer<std::uint8_t>(i.bytes[position]);
        subopcode |= std::uint32_t(byte & 0x7f) << ((position - 1) * 7);
        if (!(byte & 0x80))
            return subopcode <= 17 ? std::optional<std::uint8_t>{static_cast<std::uint8_t>(subopcode)} : std::nullopt;
    }
    return {};
}
bool valid_bulk_memory_indices(const Instruction &i, const WasmMetadata *metadata, std::uint8_t subopcode) {
    if (subopcode <= 7) return true;
    if (!metadata) return false;
    if (subopcode >= 12) {
        const auto table_count = static_cast<std::uint64_t>(metadata->imported_tables) + metadata->defined_tables;
        if (subopcode == 13) {
            const auto element = immediate(i, 0);
            return element && *element < metadata->element_segments.size();
        }
        if (table_count != 1) return false;
        if (subopcode == 12) {
            const auto element = immediate(i, 0), table = immediate(i, 1);
            return element && *element < metadata->element_segments.size() && table && *table == 0;
        }
        if (subopcode == 14) {
            const auto destination = immediate(i, 0), source = immediate(i, 1);
            return destination && *destination == 0 && source && *source == 0;
        }
        const auto table = immediate(i, 0);
        return table && *table == 0;
    }
    const auto memory_count = static_cast<std::uint64_t>(metadata->imported_memories) + metadata->defined_memories;
    if (subopcode == 9) {
        const auto data = immediate(i, 0);
        return data && *data < metadata->data_segments.size();
    }
    if (memory_count != 1) return false;
    if (subopcode == 8) {
        const auto data = immediate(i, 0), memory = immediate(i, 1);
        return data && *data < metadata->data_segments.size() && memory && *memory == 0;
    }
    if (subopcode == 10) {
        const auto destination = immediate(i, 0), source = immediate(i, 1);
        return destination && *destination == 0 && source && *source == 0;
    }
    const auto memory = immediate(i, 0);
    return memory && *memory == 0;
}
std::optional<std::uint32_t> resolved_indirect_target(const WasmMetadata *metadata,
                                                      std::uint32_t type_index,
                                                      const ExpressionPtr &table_index) {
    if (!metadata || !table_index || table_index->type != integer(32) ||
        !metadata->initial_table_complete ||
        static_cast<std::uint64_t>(metadata->imported_tables) + metadata->defined_tables != 1 ||
        std::any_of(metadata->exports.begin(), metadata->exports.end(), [](const WasmExport &entry) {
            return entry.kind == WasmExternalKind::table && entry.index == 0;
        }))
        return {};
    const auto *constant_index = std::get_if<ConstantValue>(&table_index->value);
    if (!constant_index || constant_index->value > UINT32_MAX ||
        constant_index->value >= metadata->initial_table_element_count)
        return {};
    const auto slot = static_cast<std::uint32_t>(constant_index->value);
    const auto element = std::lower_bound(metadata->initial_table_elements.begin(),
        metadata->initial_table_elements.end(), slot,
        [](const WasmTableElement &candidate, std::uint32_t value) { return candidate.slot < value; });
    if (element == metadata->initial_table_elements.end() || element->slot != slot ||
        element->function_index >= metadata->function_type_indices.size() ||
        metadata->function_type_indices[element->function_index] != type_index)
        return {};
    return element->function_index;
}
struct OpInfo { unsigned pops; ValueType input, output; std::string_view op; bool comparison = false; };
std::optional<OpInfo> numeric(std::uint8_t op) {
    const auto i32 = integer(32), i64 = integer(64), f32 = floating(32), f64 = floating(64);
    // WebAssembly comparisons produce an i32 value (0 or 1), not an abstract
    // one-bit Boolean. Keeping that stack type is required for patterns such
    // as `i32.eq; if`, `i32.eqz`, and integer arithmetic on comparison results.
    if (op == 0x45) return OpInfo{1, i32, i32, "eqz"};
    if (op == 0x50) return OpInfo{1, i64, i32, "eqz"};
    if (op >= 0x46 && op <= 0x4f) return OpInfo{2, i32, i32, std::array<std::string_view,10>{"eq","ne","slt","ult","sgt","ugt","sle","ule","sge","uge"}[op-0x46], true};
    if (op >= 0x51 && op <= 0x5a) return OpInfo{2, i64, i32, std::array<std::string_view,10>{"eq","ne","slt","ult","sgt","ugt","sle","ule","sge","uge"}[op-0x51], true};
    if (op >= 0x5b && op <= 0x60) return OpInfo{2, f32, i32, std::array<std::string_view,6>{"eq","ne","lt","gt","le","ge"}[op-0x5b], true};
    if (op >= 0x61 && op <= 0x66) return OpInfo{2, f64, i32, std::array<std::string_view,6>{"eq","ne","lt","gt","le","ge"}[op-0x61], true};
    if (op >= 0x67 && op <= 0x69) return OpInfo{1, i32, i32, std::array<std::string_view,3>{"clz","ctz","popcnt"}[op-0x67]};
    if (op >= 0x6a && op <= 0x78) return OpInfo{2, i32, i32, std::array<std::string_view,15>{"add","sub","mul","wasm_i32_div_s_trap_zero_or_overflow","wasm_i32_div_u_trap_zero","wasm_i32_rem_s_trap_zero","wasm_i32_rem_u_trap_zero","and","or","xor","shl","shr_s","shr_u","rotl","rotr"}[op-0x6a]};
    if (op >= 0x79 && op <= 0x7b) return OpInfo{1, i64, i64, std::array<std::string_view,3>{"clz","ctz","popcnt"}[op-0x79]};
    if (op >= 0x7c && op <= 0x8a) return OpInfo{2, i64, i64, std::array<std::string_view,15>{"add","sub","mul","wasm_i64_div_s_trap_zero_or_overflow","wasm_i64_div_u_trap_zero","wasm_i64_rem_s_trap_zero","wasm_i64_rem_u_trap_zero","and","or","xor","shl","shr_s","shr_u","rotl","rotr"}[op-0x7c]};
    if (op >= 0x8b && op <= 0x98) return OpInfo{(op<=0x91)?1u:2u,f32,f32,std::array<std::string_view,14>{"abs","neg","ceil","floor","trunc","nearest","sqrt","add","sub","mul","div","wasm_f32_min","wasm_f32_max","copysign"}[op-0x8b]};
    if (op >= 0x99 && op <= 0xa6) return OpInfo{(op<=0x9f)?1u:2u,f64,f64,std::array<std::string_view,14>{"abs","neg","ceil","floor","trunc","nearest","sqrt","add","sub","mul","div","wasm_f64_min","wasm_f64_max","copysign"}[op-0x99]};
    return {};
}
struct ConversionInfo { ValueType input, output; std::string_view operation; };
std::optional<ConversionInfo> saturating_conversion(std::uint8_t subopcode) {
    const auto i32 = integer(32), i64 = integer(64), f32 = floating(32), f64 = floating(64);
    static constexpr std::array<std::string_view, 8> names{
        "wasm_i32_trunc_sat_f32_s", "wasm_i32_trunc_sat_f32_u",
        "wasm_i32_trunc_sat_f64_s", "wasm_i32_trunc_sat_f64_u",
        "wasm_i64_trunc_sat_f32_s", "wasm_i64_trunc_sat_f32_u",
        "wasm_i64_trunc_sat_f64_s", "wasm_i64_trunc_sat_f64_u"};
    if (subopcode >= names.size()) return {};
    const std::array<ValueType, 8> inputs{f32, f32, f64, f64, f32, f32, f64, f64};
    const std::array<ValueType, 8> outputs{i32, i32, i32, i32, i64, i64, i64, i64};
    return ConversionInfo{inputs[subopcode], outputs[subopcode], names[subopcode]};
}
std::optional<ConversionInfo> conversion(std::uint8_t op) {
    const auto i32=integer(32), i64=integer(64), f32=floating(32), f64=floating(64);
    switch (op) {
    case 0xa7: return ConversionInfo{i64,i32,"wasm_i32_wrap_i64"};
    case 0xa8: return ConversionInfo{f32,i32,"wasm_i32_trunc_f32_s_trap"};
    case 0xa9: return ConversionInfo{f32,i32,"wasm_i32_trunc_f32_u_trap"};
    case 0xaa: return ConversionInfo{f64,i32,"wasm_i32_trunc_f64_s_trap"};
    case 0xab: return ConversionInfo{f64,i32,"wasm_i32_trunc_f64_u_trap"};
    case 0xac: return ConversionInfo{i32,i64,"wasm_i64_extend_i32_s"};
    case 0xad: return ConversionInfo{i32,i64,"wasm_i64_extend_i32_u"};
    case 0xae: return ConversionInfo{f32,i64,"wasm_i64_trunc_f32_s_trap"};
    case 0xaf: return ConversionInfo{f32,i64,"wasm_i64_trunc_f32_u_trap"};
    case 0xb0: return ConversionInfo{f64,i64,"wasm_i64_trunc_f64_s_trap"};
    case 0xb1: return ConversionInfo{f64,i64,"wasm_i64_trunc_f64_u_trap"};
    case 0xb2: return ConversionInfo{i32,f32,"wasm_f32_convert_i32_s"};
    case 0xb3: return ConversionInfo{i32,f32,"wasm_f32_convert_i32_u"};
    case 0xb4: return ConversionInfo{i64,f32,"wasm_f32_convert_i64_s"};
    case 0xb5: return ConversionInfo{i64,f32,"wasm_f32_convert_i64_u"};
    case 0xb6: return ConversionInfo{f64,f32,"wasm_f32_demote_f64"};
    case 0xb7: return ConversionInfo{i32,f64,"wasm_f64_convert_i32_s"};
    case 0xb8: return ConversionInfo{i32,f64,"wasm_f64_convert_i32_u"};
    case 0xb9: return ConversionInfo{i64,f64,"wasm_f64_convert_i64_s"};
    case 0xba: return ConversionInfo{i64,f64,"wasm_f64_convert_i64_u"};
    case 0xbb: return ConversionInfo{f32,f64,"wasm_f64_promote_f32"};
    case 0xbc: return ConversionInfo{f32,i32,"wasm_i32_reinterpret_f32"};
    case 0xbd: return ConversionInfo{f64,i64,"wasm_i64_reinterpret_f64"};
    case 0xbe: return ConversionInfo{i32,f32,"wasm_f32_reinterpret_i32"};
    case 0xbf: return ConversionInfo{i64,f64,"wasm_f64_reinterpret_i64"};
    default: return {};
    }
}
struct SignExtensionInfo { ValueType type; unsigned source_bits; };
std::optional<SignExtensionInfo> sign_extension(std::uint8_t op) {
    switch (op) {
    case 0xc0: return SignExtensionInfo{integer(32), 8};
    case 0xc1: return SignExtensionInfo{integer(32), 16};
    case 0xc2: return SignExtensionInfo{integer(64), 8};
    case 0xc3: return SignExtensionInfo{integer(64), 16};
    case 0xc4: return SignExtensionInfo{integer(64), 32};
    default: return {};
    }
}
ExpressionPtr integer_trap_condition(std::uint8_t op, const ExpressionPtr &left,
                                     const ExpressionPtr &right, unsigned bits) {
    const auto i32 = integer(32);
    const auto zero = constant(0, integer(bits));
    const auto divisor_zero = binary("eq", right, zero, i32);
    if (op == 0x6d || op == 0x7f) {
        const auto minimum = constant(std::uint64_t{1} << (bits - 1), integer(bits));
        const auto minus_one_bits = bits == 64 ? std::numeric_limits<std::uint64_t>::max()
                                                : (std::uint64_t{1} << bits) - 1;
        const auto minus_one = constant(minus_one_bits, integer(bits));
        const auto minimum_divided_by_minus_one = binary(
            "and", binary("eq", left, minimum, i32), binary("eq", right, minus_one, i32), i32);
        return binary("or", divisor_zero, minimum_divided_by_minus_one, i32);
    }
    return divisor_zero;
}
ExpressionPtr float_to_integer_trap_condition(std::uint8_t op, const ExpressionPtr &value) {
    const auto info = conversion(op);
    if (!info) return {};
    // This named Boolean operator denotes the exact MVP trap condition:
    // NaN or truncation toward zero would produce a value outside the target range.
    return unary(std::string(info->operation) + "_condition", value, integer(32));
}
ExpressionPtr wasm_memory_access_trap_condition(const ExpressionPtr &base,
                                                std::uint32_t offset,
                                                unsigned access_bytes) {
    auto effective_address = unary("zext", base, integer(64));
    if (offset != 0)
        effective_address = binary("add", std::move(effective_address),
                                   constant(offset, integer(64)), integer(64));
    return unary("wasm_memory_access_out_of_bounds_length_" + std::to_string(access_bytes),
                 std::move(effective_address), integer(32));
}
struct MemoryOpInfo {
    bool store = false;
    ValueType stack_type;
    ValueType access_type;
    unsigned maximum_alignment_exponent = 0;
};
struct SimdMemoryOpInfo {
    bool store = false;
    unsigned access_bits = 128;
    ValueType stack_type = vector(128);
    ValueType memory_type = vector(128);
    std::string_view load_operation;
    unsigned maximum_alignment_exponent = 4;
    bool lane_indexed = false;
};
struct SimdLaneOpInfo {
    bool replace = false;
    unsigned lane_count = 0;
    ValueType scalar_type;
    std::string_view name;
};
struct SimdSplatOpInfo {
    ValueType scalar_type;
    std::string_view name;
};
struct SimdRelaxedOpInfo {
    std::string_view name;
    unsigned input_count = 0;
};
std::optional<SimdRelaxedOpInfo> simd_relaxed_op(std::uint32_t subopcode) {
    static constexpr std::array<std::string_view, 20> names{
        "i8x16.relaxed_swizzle",
        "i32x4.relaxed_trunc_f32x4_s", "i32x4.relaxed_trunc_f32x4_u",
        "i32x4.relaxed_trunc_f64x2_s_zero", "i32x4.relaxed_trunc_f64x2_u_zero",
        "f32x4.relaxed_madd", "f32x4.relaxed_nmadd",
        "f64x2.relaxed_madd", "f64x2.relaxed_nmadd",
        "i8x16.relaxed_laneselect", "i16x8.relaxed_laneselect",
        "i32x4.relaxed_laneselect", "i64x2.relaxed_laneselect",
        "f32x4.relaxed_min", "f32x4.relaxed_max",
        "f64x2.relaxed_min", "f64x2.relaxed_max",
        "i16x8.relaxed_q15mulr_s", "i16x8.relaxed_dot_i8x16_i7x16_s",
        "i32x4.relaxed_dot_i8x16_i7x16_add_s"};
    if (subopcode < 0x100 || subopcode > 0x113) return {};
    const auto index = static_cast<std::size_t>(subopcode - 0x100);
    const unsigned inputs = ((index >= 5 && index <= 12) || index == 19) ? 3u
        : index >= 1 && index <= 4 ? 1u : 2u;
    return SimdRelaxedOpInfo{names[index], inputs};
}
std::string simd_relaxed_intrinsic_name(std::string_view mnemonic) {
    std::string name = "wasm_";
    name.reserve(name.size() + mnemonic.size());
    for (const char ch : mnemonic) name.push_back(ch == '.' ? '_' : ch);
    return name;
}
std::optional<SimdSplatOpInfo> simd_splat_op(std::uint32_t subopcode) {
    switch (subopcode) {
    case 0x0f: return SimdSplatOpInfo{integer(32), "wasm_i8x16_splat"};
    case 0x10: return SimdSplatOpInfo{integer(32), "wasm_i16x8_splat"};
    case 0x11: return SimdSplatOpInfo{integer(32), "wasm_i32x4_splat"};
    case 0x12: return SimdSplatOpInfo{integer(64), "wasm_i64x2_splat"};
    case 0x13: return SimdSplatOpInfo{floating(32), "wasm_f32x4_splat"};
    case 0x14: return SimdSplatOpInfo{floating(64), "wasm_f64x2_splat"};
    default: return {};
    }
}
struct SimdIntegerUnaryInfo { std::string_view name; ValueType result_type; };
std::optional<SimdIntegerUnaryInfo> simd_integer_unary(std::uint32_t subopcode) {
    switch (subopcode) {
    case 0x60: return SimdIntegerUnaryInfo{"wasm_i8x16_abs", vector(128)};
    case 0x61: return SimdIntegerUnaryInfo{"wasm_i8x16_neg", vector(128)};
    case 0x62: return SimdIntegerUnaryInfo{"wasm_i8x16_popcnt", vector(128)};
    case 0x63: return SimdIntegerUnaryInfo{"wasm_i8x16_all_true", integer(32)};
    case 0x64: return SimdIntegerUnaryInfo{"wasm_i8x16_bitmask", integer(32)};
    case 0x80: return SimdIntegerUnaryInfo{"wasm_i16x8_abs", vector(128)};
    case 0x81: return SimdIntegerUnaryInfo{"wasm_i16x8_neg", vector(128)};
    case 0x83: return SimdIntegerUnaryInfo{"wasm_i16x8_all_true", integer(32)};
    case 0x84: return SimdIntegerUnaryInfo{"wasm_i16x8_bitmask", integer(32)};
    case 0xa0: return SimdIntegerUnaryInfo{"wasm_i32x4_abs", vector(128)};
    case 0xa1: return SimdIntegerUnaryInfo{"wasm_i32x4_neg", vector(128)};
    case 0xa3: return SimdIntegerUnaryInfo{"wasm_i32x4_all_true", integer(32)};
    case 0xa4: return SimdIntegerUnaryInfo{"wasm_i32x4_bitmask", integer(32)};
    case 0xc0: return SimdIntegerUnaryInfo{"wasm_i64x2_abs", vector(128)};
    case 0xc1: return SimdIntegerUnaryInfo{"wasm_i64x2_neg", vector(128)};
    case 0xc3: return SimdIntegerUnaryInfo{"wasm_i64x2_all_true", integer(32)};
    case 0xc4: return SimdIntegerUnaryInfo{"wasm_i64x2_bitmask", integer(32)};
    default: return {};
    }
}
std::optional<SimdLaneOpInfo> simd_lane_op(std::uint32_t subopcode) {
    const auto i32 = integer(32), i64 = integer(64), f32 = floating(32), f64 = floating(64);
    switch (subopcode) {
    case 21: return SimdLaneOpInfo{false, 16, i32, "wasm_i8x16_extract_lane_s"};
    case 22: return SimdLaneOpInfo{false, 16, i32, "wasm_i8x16_extract_lane_u"};
    case 23: return SimdLaneOpInfo{true, 16, i32, "wasm_i8x16_replace_lane"};
    case 24: return SimdLaneOpInfo{false, 8, i32, "wasm_i16x8_extract_lane_s"};
    case 25: return SimdLaneOpInfo{false, 8, i32, "wasm_i16x8_extract_lane_u"};
    case 26: return SimdLaneOpInfo{true, 8, i32, "wasm_i16x8_replace_lane"};
    case 27: return SimdLaneOpInfo{false, 4, i32, "wasm_i32x4_extract_lane"};
    case 28: return SimdLaneOpInfo{true, 4, i32, "wasm_i32x4_replace_lane"};
    case 29: return SimdLaneOpInfo{false, 2, i64, "wasm_i64x2_extract_lane"};
    case 30: return SimdLaneOpInfo{true, 2, i64, "wasm_i64x2_replace_lane"};
    case 31: return SimdLaneOpInfo{false, 4, f32, "wasm_f32x4_extract_lane"};
    case 32: return SimdLaneOpInfo{true, 4, f32, "wasm_f32x4_replace_lane"};
    case 33: return SimdLaneOpInfo{false, 2, f64, "wasm_f64x2_extract_lane"};
    case 34: return SimdLaneOpInfo{true, 2, f64, "wasm_f64x2_replace_lane"};
    default: return {};
    }
}
std::optional<std::uint32_t> simd_subopcode(const Instruction &instruction) {
    if (instruction.length < 2 || std::to_integer<std::uint8_t>(instruction.bytes[0]) != 0xfd)
        return {};
    std::uint32_t value = 0;
    for (std::size_t position = 1; position < instruction.length && position < instruction.bytes.size() && position < 6; ++position) {
        const auto byte = std::to_integer<std::uint8_t>(instruction.bytes[position]);
        value |= std::uint32_t(byte & 0x7f) << ((position - 1) * 7);
        if (!(byte & 0x80)) return value;
    }
    return {};
}
std::optional<std::string_view> simd_integer_shift(std::uint32_t subopcode) {
    static constexpr std::array<std::string_view, 12> names{
        "wasm_i8x16_shl", "wasm_i8x16_shr_s", "wasm_i8x16_shr_u",
        "wasm_i16x8_shl", "wasm_i16x8_shr_s", "wasm_i16x8_shr_u",
        "wasm_i32x4_shl", "wasm_i32x4_shr_s", "wasm_i32x4_shr_u",
        "wasm_i64x2_shl", "wasm_i64x2_shr_s", "wasm_i64x2_shr_u"};
    for (std::size_t width = 0; width < 4; ++width) {
        const auto first = std::array<std::uint32_t, 4>{0x6b, 0x8b, 0xab, 0xcb}[width];
        if (subopcode >= first && subopcode < first + 3)
            return names[width * 3 + subopcode - first];
    }
    return {};
}
std::optional<std::string_view> simd_float_unary(std::uint32_t subopcode) {
    switch (subopcode) {
    case 0x67: return "f32x4.ceil";
    case 0x68: return "f32x4.floor";
    case 0x69: return "f32x4.trunc";
    case 0x6a: return "f32x4.nearest";
    case 0x74: return "f64x2.ceil";
    case 0x75: return "f64x2.floor";
    case 0x7a: return "f64x2.trunc";
    case 0x94: return "f64x2.nearest";
    case 0xe0: return "f32x4.abs";
    case 0xe1: return "f32x4.neg";
    case 0xe3: return "f32x4.sqrt";
    case 0xec: return "f64x2.abs";
    case 0xed: return "f64x2.neg";
    case 0xef: return "f64x2.sqrt";
    default: return {};
    }
}
std::optional<std::string_view> simd_float_binary(std::uint32_t subopcode) {
    switch (subopcode) {
    case 0xe4: return "f32x4.add";
    case 0xe5: return "f32x4.sub";
    case 0xe6: return "f32x4.mul";
    case 0xe7: return "f32x4.div";
    case 0xe8: return "f32x4.min";
    case 0xe9: return "f32x4.max";
    case 0xea: return "f32x4.pmin";
    case 0xeb: return "f32x4.pmax";
    case 0xf0: return "f64x2.add";
    case 0xf1: return "f64x2.sub";
    case 0xf2: return "f64x2.mul";
    case 0xf3: return "f64x2.div";
    case 0xf4: return "f64x2.min";
    case 0xf5: return "f64x2.max";
    case 0xf6: return "f64x2.pmin";
    case 0xf7: return "f64x2.pmax";
    default: return {};
    }
}
std::optional<std::string_view> simd_conversion(std::uint32_t subopcode) {
    switch (subopcode) {
    case 0x5e: return "f32x4.demote_f64x2_zero";
    case 0x5f: return "f64x2.promote_low_f32x4";
    case 0xf8: return "i32x4.trunc_sat_f32x4_s";
    case 0xf9: return "i32x4.trunc_sat_f32x4_u";
    case 0xfa: return "f32x4.convert_i32x4_s";
    case 0xfb: return "f32x4.convert_i32x4_u";
    case 0xfc: return "i32x4.trunc_sat_f64x2_s_zero";
    case 0xfd: return "i32x4.trunc_sat_f64x2_u_zero";
    case 0xfe: return "f64x2.convert_low_i32x4_s";
    case 0xff: return "f64x2.convert_low_i32x4_u";
    default: return {};
    }
}
std::optional<std::string_view> simd_integer_extmul(std::uint32_t subopcode) {
    switch (subopcode) {
    case 0x9c: return "i16x8.extmul_low_i8x16_s";
    case 0x9d: return "i16x8.extmul_high_i8x16_s";
    case 0x9e: return "i16x8.extmul_low_i8x16_u";
    case 0x9f: return "i16x8.extmul_high_i8x16_u";
    case 0xbc: return "i32x4.extmul_low_i16x8_s";
    case 0xbd: return "i32x4.extmul_high_i16x8_s";
    case 0xbe: return "i32x4.extmul_low_i16x8_u";
    case 0xbf: return "i32x4.extmul_high_i16x8_u";
    case 0xdc: return "i64x2.extmul_low_i32x4_s";
    case 0xdd: return "i64x2.extmul_high_i32x4_s";
    case 0xde: return "i64x2.extmul_low_i32x4_u";
    case 0xdf: return "i64x2.extmul_high_i32x4_u";
    default: return {};
    }
}
bool simd_integer_extend_or_pairwise_add(std::uint32_t subopcode) {
    return (subopcode >= 0x7c && subopcode <= 0x7f) ||
           (subopcode >= 0x87 && subopcode <= 0x8a) ||
           (subopcode >= 0xa7 && subopcode <= 0xaa) ||
           (subopcode >= 0xc7 && subopcode <= 0xca);
}
bool simd_integer_narrow(std::uint32_t subopcode) {
    return subopcode == 0x65 || subopcode == 0x66 || subopcode == 0x85 || subopcode == 0x86;
}
std::optional<SimdMemoryOpInfo> simd_memory_op(std::uint32_t subopcode) {
    const auto opaque = vector(128);
    switch (subopcode) {
    case 0: return SimdMemoryOpInfo{false, 128, opaque, opaque, {}, 4};
    case 1: return SimdMemoryOpInfo{false, 64, vector(128, TypeKind::integer, 16, 8, true), vector(64), "wasm_v128_load8x8_s", 3};
    case 2: return SimdMemoryOpInfo{false, 64, vector(128, TypeKind::integer, 16, 8), vector(64), "wasm_v128_load8x8_u", 3};
    case 3: return SimdMemoryOpInfo{false, 64, vector(128, TypeKind::integer, 32, 4, true), vector(64), "wasm_v128_load16x4_s", 3};
    case 4: return SimdMemoryOpInfo{false, 64, vector(128, TypeKind::integer, 32, 4), vector(64), "wasm_v128_load16x4_u", 3};
    case 5: return SimdMemoryOpInfo{false, 64, vector(128, TypeKind::integer, 64, 2, true), vector(64), "wasm_v128_load32x2_s", 3};
    case 6: return SimdMemoryOpInfo{false, 64, vector(128, TypeKind::integer, 64, 2), vector(64), "wasm_v128_load32x2_u", 3};
    case 7: return SimdMemoryOpInfo{false, 8, vector(128, TypeKind::integer, 8, 16), integer(8), "wasm_v128_load8_splat", 0};
    case 8: return SimdMemoryOpInfo{false, 16, vector(128, TypeKind::integer, 16, 8), integer(16), "wasm_v128_load16_splat", 1};
    case 9: return SimdMemoryOpInfo{false, 32, vector(128, TypeKind::integer, 32, 4), integer(32), "wasm_v128_load32_splat", 2};
    case 10: return SimdMemoryOpInfo{false, 64, vector(128, TypeKind::integer, 64, 2), integer(64), "wasm_v128_load64_splat", 3};
    case 11: return SimdMemoryOpInfo{true, 128, opaque, opaque, {}, 4};
    case 84: return SimdMemoryOpInfo{false, 8, opaque, integer(8), {}, 0, true};
    case 85: return SimdMemoryOpInfo{false, 16, opaque, integer(16), {}, 1, true};
    case 86: return SimdMemoryOpInfo{false, 32, opaque, integer(32), {}, 2, true};
    case 87: return SimdMemoryOpInfo{false, 64, opaque, integer(64), {}, 3, true};
    case 88: return SimdMemoryOpInfo{true, 8, opaque, integer(8), {}, 0, true};
    case 89: return SimdMemoryOpInfo{true, 16, opaque, integer(16), {}, 1, true};
    case 90: return SimdMemoryOpInfo{true, 32, opaque, integer(32), {}, 2, true};
    case 91: return SimdMemoryOpInfo{true, 64, opaque, integer(64), {}, 3, true};
    case 92: return SimdMemoryOpInfo{false, 32, opaque, integer(32), "wasm_v128_load32_zero", 2};
    case 93: return SimdMemoryOpInfo{false, 64, opaque, integer(64), "wasm_v128_load64_zero", 3};
    default: return {};
    }
}
std::optional<MemoryOpInfo> memory_op(std::uint8_t op) {
    switch (op) {
    case 0x28: return MemoryOpInfo{false, integer(32), integer(32), 2};
    case 0x29: return MemoryOpInfo{false, integer(64), integer(64), 3};
    case 0x2a: return MemoryOpInfo{false, floating(32), floating(32), 2};
    case 0x2b: return MemoryOpInfo{false, floating(64), floating(64), 3};
    case 0x2c: return MemoryOpInfo{false, integer(32), integer(8, true), 0};
    case 0x2d: return MemoryOpInfo{false, integer(32), integer(8), 0};
    case 0x2e: return MemoryOpInfo{false, integer(32), integer(16, true), 1};
    case 0x2f: return MemoryOpInfo{false, integer(32), integer(16), 1};
    case 0x30: return MemoryOpInfo{false, integer(64), integer(8, true), 0};
    case 0x31: return MemoryOpInfo{false, integer(64), integer(8), 0};
    case 0x32: return MemoryOpInfo{false, integer(64), integer(16, true), 1};
    case 0x33: return MemoryOpInfo{false, integer(64), integer(16), 1};
    case 0x34: return MemoryOpInfo{false, integer(64), integer(32, true), 2};
    case 0x35: return MemoryOpInfo{false, integer(64), integer(32), 2};
    case 0x36: return MemoryOpInfo{true, integer(32), integer(32), 2};
    case 0x37: return MemoryOpInfo{true, integer(64), integer(64), 3};
    case 0x38: return MemoryOpInfo{true, floating(32), floating(32), 2};
    case 0x39: return MemoryOpInfo{true, floating(64), floating(64), 3};
    case 0x3a: return MemoryOpInfo{true, integer(32), integer(8), 0};
    case 0x3b: return MemoryOpInfo{true, integer(32), integer(16), 1};
    case 0x3c: return MemoryOpInfo{true, integer(64), integer(8), 0};
    case 0x3d: return MemoryOpInfo{true, integer(64), integer(16), 1};
    case 0x3e: return MemoryOpInfo{true, integer(64), integer(32), 2};
    default: return {};
    }
}
Error unsupported(std::string why) { return {ErrorCode::unsupported, "WebAssembly lift unsupported: " + std::move(why)}; }
Result<std::pair<std::uint64_t, std::uint64_t>> memory_immediates(const Instruction &instruction,
                                                                  const MemoryOpInfo &info,
                                                                  const WasmMetadata *metadata) {
    if (!metadata || static_cast<std::uint64_t>(metadata->imported_memories) + metadata->defined_memories != 1)
        return unsupported("scalar memory operation requires exactly one validated module memory");
    const auto alignment = immediate(instruction, 0);
    const auto offset = immediate(instruction, 1);
    if (!alignment || !offset)
        return unsupported("memory alignment or offset immediate unavailable");
    if (*alignment > info.maximum_alignment_exponent)
        return unsupported("memory alignment exceeds the access natural alignment");
    if (*offset > std::numeric_limits<std::uint32_t>::max())
        return unsupported("memory offset exceeds the Wasm32 address width");
    return std::pair{*alignment, *offset};
}
}

Result<LiftedFunction> lift_wasm_function(const FunctionRecord &function, const FunctionSnapshot &snapshot) {
    return lift_wasm_function(function, snapshot, nullptr);
}

Result<LiftedFunction> lift_wasm_function(const FunctionRecord &function, const FunctionSnapshot &snapshot,
                                           const WasmMetadata *metadata) {
    std::map<std::uint64_t, std::shared_ptr<const BasicBlock>> blocks;
    for (const auto &b : snapshot.blocks) {
        if (!b) return Error{ErrorCode::invalid_argument, "WebAssembly snapshot contains a null block"};
        blocks.emplace(b->id.value, b);
    }
    std::vector<const InstructionFact *> code;
    for (const auto id : function.blocks) {
        const auto it = blocks.find(id.value);
        if (it == blocks.end()) return Error{ErrorCode::invalid_argument, "WebAssembly function block is missing from snapshot"};
        for (const auto &fact : it->second->instructions) {
            if (!fact) return Error{ErrorCode::invalid_argument, "WebAssembly block contains a null instruction"};
            if (fact->instruction.context.architecture != Architecture::wasm)
                return unsupported("function contains a non-wasm instruction");
            code.push_back(fact.get());
        }
    }
    std::sort(code.begin(), code.end(), [](auto a, auto b) {
        const auto aa = a->instruction.address, bb = b->instruction.address;
        return aa.space.value != bb.space.value ? aa.space.value < bb.space.value : aa.offset < bb.offset;
    });
    if (code.empty()) return unsupported("empty or unavailable function body");

    constexpr std::size_t max_instructions = 100000;
    constexpr std::size_t max_blocks = 16384;
    constexpr std::size_t max_nesting = 128;
    constexpr std::size_t max_stack = 128;
    constexpr std::size_t max_switch_cases = 128;
    if (code.size() > max_instructions) return Error{ErrorCode::resource_limit, "WebAssembly function exceeds the instruction limit"};

    const auto function_index = static_cast<std::uint32_t>(function.entry.space.value);
    const auto signature_for = [&](std::uint64_t index) -> const WasmFunctionType * {
        if (!metadata || index > UINT32_MAX || index >= metadata->function_type_indices.size()) return nullptr;
        const auto type_index = metadata->function_type_indices[static_cast<std::size_t>(index)];
        if (type_index >= metadata->function_types.size()) return nullptr;
        return &metadata->function_types[type_index];
    };
    const WasmFunctionType *function_signature = function.entry.space.value <= UINT32_MAX
        ? signature_for(function_index) : nullptr;
    if (function_signature && (function_signature->result_count != function_signature->result_types.size() ||
        function_signature->result_types.size() > max_stack))
        return unsupported("function result metadata is inconsistent or exceeds the 128-value bound");
    const WasmFunctionLocals *declared_locals = nullptr;
    if (metadata) {
        const auto found = std::find_if(metadata->function_locals.begin(), metadata->function_locals.end(),
            [&](const WasmFunctionLocals &item) { return item.function_index == function_index; });
        if (found != metadata->function_locals.end() &&
            std::find_if(std::next(found), metadata->function_locals.end(), [&](const WasmFunctionLocals &item) {
                return item.function_index == function_index;
            }) != metadata->function_locals.end())
            return unsupported("function local metadata contains duplicate function entries");
        if (found != metadata->function_locals.end() && found->function_index == function_index)
            declared_locals = &*found;
    }
    std::vector<ValueType> local_types;
    if (function_signature) {
        if (function_signature->parameter_count != function_signature->parameter_types.size() ||
            function_signature->result_count != function_signature->result_types.size())
            return unsupported("function signature metadata is inconsistent");
        if (function_signature->parameter_types.size() > 256)
            return Error{ErrorCode::resource_limit, "WebAssembly typed local lifting is limited to 256 parameters and locals"};
        for (const auto type : function_signature->parameter_types) {
            const auto converted = wasm_value_type(type);
            if (!converted) return unsupported("function signature contains an unsupported parameter type");
            local_types.push_back(*converted);
        }
    }
    if (declared_locals) {
        if (declared_locals->value_types.size() > 256 - local_types.size())
            return Error{ErrorCode::resource_limit, "WebAssembly typed local lifting is limited to 256 parameters and locals"};
        for (const auto type : declared_locals->value_types) {
            const auto converted = wasm_value_type(type);
            if (!converted) return unsupported("function local metadata contains an unsupported type");
            local_types.push_back(*converted);
        }
    }
    if (local_types.size() > 256)
        return Error{ErrorCode::resource_limit, "WebAssembly typed local lifting is limited to 256 parameters and locals"};
    const auto local_type = [&](std::uint64_t index) -> std::optional<ValueType> {
        if (index >= local_types.size()) return {};
        return local_types[static_cast<std::size_t>(index)];
    };
    const auto local_register = [&](std::uint64_t index) -> RegisterOperand {
        const auto type = *local_type(index);
        return {RegisterBank::wasm_local, static_cast<std::uint8_t>(index), type.bits, false};
    };
    const auto local_name = [&](std::uint64_t index) {
        std::string base = index < (function_signature ? function_signature->parameter_types.size() : 0)
            ? "arg" + std::to_string(index) : "local" + std::to_string(index);
        if (metadata) {
            const auto named = std::find_if(metadata->local_names.begin(), metadata->local_names.end(),
                [&](const WasmLocalName &item) {
                    return item.function_index == function_index && item.local_index == index;
                });
            if (named != metadata->local_names.end()) base = named->name;
        }
        std::string result = "wasm_";
        for (const unsigned char ch : base)
            result.push_back((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                             (ch >= '0' && ch <= '9') || ch == '_' ? static_cast<char>(ch) : '_');
        result += "_l" + std::to_string(index);
        return result;
    };

    struct Label {
        std::uint8_t kind;
        std::size_t opener, end, else_index;
        std::vector<ValueType> parameters, result_types;
    };
    std::vector<Label> labels;
    std::vector<std::size_t> nesting;
    std::map<std::size_t, std::size_t> label_for_opener;
    std::map<std::size_t, std::size_t> label_for_end;
    std::size_t function_end = code.size();
    for (std::size_t n=0;n<code.size();++n) {
        if (code[n]->instruction.bytes.empty()) return unsupported("instruction bytes unavailable");
        const auto op=std::to_integer<std::uint8_t>(code[n]->instruction.bytes[0]);
        if (op==2||op==3||op==4) {
            auto bt=immediate(code[n]->instruction);
            if (!bt) return unsupported("block type immediate unavailable");
            const auto signed_bt=static_cast<std::int64_t>(*bt);
            std::vector<ValueType> block_parameters, result_types;
            if (signed_bt == -1) result_types.push_back(integer(32));
            else if (signed_bt == -2) result_types.push_back(integer(64));
            else if (signed_bt == -3) result_types.push_back(floating(32));
            else if (signed_bt == -4) result_types.push_back(floating(64));
            else if (signed_bt != -64) {
                if (!metadata || signed_bt < 0 || static_cast<std::uint64_t>(signed_bt) >= metadata->function_types.size())
                    return unsupported("indexed block type is unavailable or out of range");
                const auto &signature = metadata->function_types[static_cast<std::size_t>(signed_bt)];
                if (signature.parameter_count != signature.parameter_types.size() ||
                    signature.result_count != signature.result_types.size())
                    return unsupported("indexed block type metadata is inconsistent");
                for (const auto type : signature.parameter_types) {
                    const auto converted = wasm_value_type(type);
                    if (!converted) return unsupported("indexed block type contains an unsupported parameter type");
                    block_parameters.push_back(*converted);
                }
                if (signature.result_types.size() > max_stack)
                    return Error{ErrorCode::resource_limit, "WebAssembly block result count exceeds 128 values"};
                for (const auto type : signature.result_types) {
                    const auto converted = wasm_value_type(type);
                    if (!converted) return unsupported("indexed block type contains an unsupported result type");
                    result_types.push_back(*converted);
                }
            }
            if (nesting.size() >= max_nesting) return Error{ErrorCode::resource_limit, "WebAssembly control nesting exceeds 128 labels"};
            label_for_opener[n]=labels.size(); labels.push_back({op,n,code.size(),code.size(),
                std::move(block_parameters), std::move(result_types)}); nesting.push_back(labels.size()-1);
        } else if (op==5) {
            if (nesting.empty() || labels[nesting.back()].kind != 4 || labels[nesting.back()].else_index != code.size()) return unsupported("malformed else nesting");
            labels[nesting.back()].else_index=n;
        } else if (op==0x0b && !nesting.empty()) {
            auto &label=labels[nesting.back()]; label.end=n; label_for_end[n]=nesting.back(); nesting.pop_back();
        } else if (op==0x0b) {
            if (n + 1 != code.size()) return unsupported("instructions follow the function end");
            function_end = n;
        }
    }
    if (!nesting.empty()) return unsupported("unterminated structured control");
    for (const auto &label : labels)
        if (label.kind == 4 && label.else_index == code.size() && !label.result_types.empty())
            return unsupported("a result-typed if requires an else arm");

    if (function_end != code.size()-1) return unsupported("function has no final end operator");
    std::vector<ValueType> function_label_results;
    if (function_signature) {
        for (const auto type : function_signature->result_types) {
            const auto converted = wasm_value_type(type);
            if (!converted) return unsupported("function label contains an unsupported result type");
            function_label_results.push_back(*converted);
        }
    }
    const auto function_label = labels.size();
    labels.push_back({0xff, 0, function_end, code.size(), {}, function_label_results});
    struct Edge {
        std::size_t target;
        BlockEdgeKind kind;
        std::optional<std::size_t> label;
        std::optional<std::size_t> bridge;
    };
    std::set<std::size_t> boundaries{0, code.size()};
    std::vector<std::vector<std::size_t>> active_labels(code.size());
    struct TableTarget { std::optional<std::uint64_t> value; std::size_t label; std::size_t target; };
    const auto table_targets = [&](std::size_t n) -> Result<std::vector<TableTarget>> {
        const auto &instruction = code[n]->instruction;
        const auto count = immediate(instruction, 0);
        if (!count || *count > max_switch_cases || instruction.operands.size() != *count + 2)
            return unsupported("br_table count or target vector is malformed or exceeds the decoded bound");
        std::vector<TableTarget> targets;
        targets.reserve(static_cast<std::size_t>(*count) + 1);
        for (std::size_t operand = 0; operand <= *count; ++operand) {
            const auto depth = immediate(instruction, operand + 1);
            if (!depth || *depth >= active_labels[n].size())
                return unsupported("br_table target depth is unavailable or invalid");
            const auto label = active_labels[n][active_labels[n].size() - 1 - static_cast<std::size_t>(*depth)];
            if (label == function_label && !function_signature)
                return unsupported("br_table to the implicit function label requires its signature");
            const auto target = label == function_label ? function_end :
                labels[label].kind == 3 ? labels[label].opener + 1 : labels[label].end + 1;
            if (target >= code.size()) return unsupported("br_table target falls outside the function body");
            targets.push_back({operand < *count ? std::optional<std::uint64_t>{operand} : std::nullopt, label, target});
        }
        return targets;
    };
    for (std::size_t n=0;n<code.size();++n) {
        const auto op=std::to_integer<std::uint8_t>(code[n]->instruction.bytes[0]);
        if (op==2||op==3||op==4||op==5||op==0x0b||op==0x00) { boundaries.insert(n); boundaries.insert(n+1); }
        if (op==0x0c||op==0x0d||op==0x0e) { boundaries.insert(n); boundaries.insert(n+1); }
        for (std::size_t li=0;li<function_label;++li)
            if (labels[li].opener<n&&n<labels[li].end) active_labels[n].push_back(li);
        std::sort(active_labels[n].begin(),active_labels[n].end(),[&](auto a,auto b){return labels[a].opener<labels[b].opener;});
        active_labels[n].insert(active_labels[n].begin(), function_label);
        if (op==0x0c||op==0x0d) {
            auto depth=immediate(code[n]->instruction); if(!depth)return unsupported("branch depth unavailable");
            if(*depth>=active_labels[n].size())return unsupported("branch depth is invalid");
            const auto li=active_labels[n][active_labels[n].size()-1-static_cast<std::size_t>(*depth)];
            if (li == function_label && !function_signature)
                return unsupported("branch to the implicit function label requires its signature");
            const auto target=li==function_label?function_end:
                labels[li].kind==3?labels[li].opener+1:labels[li].end+1;
            if(target>=code.size())return unsupported("branch target falls outside the function body");
            boundaries.insert(target);
        } else if (op == 0x0e) {
            auto targets = table_targets(n); if (!targets) return targets.error();
            for (const auto &target : targets.value()) boundaries.insert(target.target);
        }
    }
    if (boundaries.size() > max_blocks + 1) return Error{ErrorCode::resource_limit, "WebAssembly CFG exceeds the block limit"};
    std::vector<std::size_t> starts(boundaries.begin(),boundaries.end());
    starts.pop_back();
    std::map<std::size_t,std::size_t> block_at;
    for(std::size_t bi=0;bi<starts.size();++bi)block_at.emplace(starts[bi],bi);
    const auto block_for=[&](std::size_t instruction)->std::optional<std::size_t>{auto it=block_at.find(instruction);return it==block_at.end()?std::nullopt:std::optional<std::size_t>{it->second};};
    std::vector<std::vector<Edge>> successors(starts.size());
    const auto add_edge=[&](std::size_t from,std::size_t target,BlockEdgeKind kind,std::optional<std::size_t> label={}) -> bool {
        auto to=block_for(target);if(!to)return false;successors[from].push_back({*to,kind,label,{}});return true;
    };
    std::vector<std::optional<std::size_t>> opener_label(code.size()),end_label(code.size());
    for(const auto &[n,li]:label_for_opener)opener_label[n]=li;
    for(const auto &[n,li]:label_for_end)end_label[n]=li;
    for(std::size_t bi=0;bi<starts.size();++bi){
        const auto finish=bi+1<starts.size()?starts[bi+1]:code.size(),n=finish-1;
        const auto op=std::to_integer<std::uint8_t>(code[n]->instruction.bytes[0]);
        const auto fallthrough=n+1;
        if(op==0x0f||op==0x00||(op==0x0b&&n==function_end))continue;
        if(op==0x0c||op==0x0d){const auto depth=*immediate(code[n]->instruction);const auto li=active_labels[n][active_labels[n].size()-1-static_cast<std::size_t>(depth)];const auto target=li==function_label?function_end:labels[li].kind==3?labels[li].opener+1:labels[li].end+1;if(!add_edge(bi,target,op==0x0c?BlockEdgeKind::jump:BlockEdgeKind::conditional_true,li))return unsupported("branch target is not a block boundary");if(op==0x0d&&fallthrough<code.size()&&!add_edge(bi,fallthrough,BlockEdgeKind::conditional_false))return unsupported("conditional fallthrough is not a block boundary");continue;}
        if (op == 0x0e) { auto targets = table_targets(n); if (!targets) return targets.error(); for (const auto &target : targets.value()) if (!add_edge(bi, target.target, BlockEdgeKind::jump, target.label)) return unsupported("br_table target is not a block boundary"); continue; }
        if(op==4){const auto li=*opener_label[n];const auto false_target=labels[li].else_index<code.size()?labels[li].else_index+1:labels[li].end+1;if(fallthrough>=code.size()||!add_edge(bi,fallthrough,BlockEdgeKind::conditional_true)||false_target>=code.size()||!add_edge(bi,false_target,BlockEdgeKind::conditional_false))return unsupported("if target is outside the function body");continue;}
        if(op==5){const auto li=active_labels[n].back();const auto target=labels[li].end+1;if(target>=code.size()||!add_edge(bi,target,BlockEdgeKind::jump,li))return unsupported("else target is outside the function body");continue;}
        if(fallthrough<code.size()&&!add_edge(bi,fallthrough,BlockEdgeKind::fallthrough))return unsupported("fallthrough is not a block boundary");
    }

    using Shape=std::vector<ValueType>;
    std::vector<std::optional<Shape>> entries(starts.size()),exits(starts.size());
    // A branch to a loop label has the loop's parameter types (empty in this
    // MVP subset); block/if labels take their result value. The normal end of
    // every typed label produces its result value.
    std::vector<std::optional<Shape>> branch_shapes(labels.size()),end_shapes(labels.size());
    std::vector<std::optional<std::size_t>> label_heights(labels.size());
    branch_shapes[function_label] = function_label_results;
    label_heights[function_label] = 0;
    std::vector<std::vector<std::size_t>> predecessors(starts.size());
    // A Wasm branch may discard temporaries while preserving the target
    // label's result operands. Remember which source stack slots feed each
    // target slot so the ordinary common-IR phi machinery can express that
    // edge-specific stack projection.
    std::vector<std::map<std::size_t, std::vector<std::size_t>>> incoming_slot_sources(starts.size());
    struct EdgeBridge {
        std::size_t source = 0, target = 0;
        BlockEdgeKind kind = BlockEdgeKind::jump;
        Address source_address{{0}, 0};
        std::vector<std::size_t> source_slots;
    };
    std::vector<EdgeBridge> edge_bridges;
    std::vector<std::size_t> work{0};std::vector<bool> queued(starts.size());queued[0]=true;entries[0]=Shape{};
    const auto shape_pop=[&](Shape &stack,ValueType expected)->Result<ValueType>{if(stack.empty())return unsupported("operand stack underflow");auto actual=stack.back();stack.pop_back();if(expected.kind!=TypeKind::unknown&&actual!=expected)return unsupported("operand stack type mismatch");return actual;};
    const auto signature_results = [&]() -> Result<std::vector<ValueType>> {
        std::vector<ValueType> result;
        if (!function_signature) return result;
        for (const auto type : function_signature->result_types) {
            const auto converted = wasm_value_type(type);
            if (!converted) return unsupported("function signature contains an unsupported result type");
            result.push_back(*converted);
        }
        return result;
    };
    const auto matching_suffix = [](const Shape &stack, const std::vector<ValueType> &types) {
        if (stack.size() < types.size()) return false;
        return std::equal(types.begin(), types.end(), stack.end() - static_cast<std::ptrdiff_t>(types.size()));
    };
    while(!work.empty()){
        const auto bi=work.back();work.pop_back();queued[bi]=false;
        Shape stack=*entries[bi];const auto begin=starts[bi],finish=bi+1<starts.size()?starts[bi+1]:code.size();
        for(std::size_t n=begin;n<finish;++n){const auto op=std::to_integer<std::uint8_t>(code[n]->instruction.bytes[0]);
            if(op==2||op==3||op==4){
                const auto li=*opener_label[n];
                if(op==4){auto c=shape_pop(stack,integer(32));if(!c)return c.error();}
                for(auto it=labels[li].parameters.rbegin();it!=labels[li].parameters.rend();++it){auto p=shape_pop(stack,*it);if(!p)return p.error();}
                label_heights[li]=stack.size();
                stack.insert(stack.end(),labels[li].parameters.begin(),labels[li].parameters.end());
                Shape end_shape=stack;
                end_shape.resize(*label_heights[li]);
                end_shape.insert(end_shape.end(), labels[li].result_types.begin(), labels[li].result_types.end());
                if(end_shapes[li]&&*end_shapes[li]!=end_shape)return unsupported("control label receives incompatible operand stacks");
                end_shapes[li]=end_shape;
                Shape branch_shape=labels[li].kind==3?stack:end_shape;
                if(branch_shapes[li]&&*branch_shapes[li]!=branch_shape)return unsupported("control label branch shape is inconsistent");
                branch_shapes[li]=std::move(branch_shape);
                continue;
            }
            if(op==1)continue;
            if(op==5){const auto li=active_labels[n].back();if(!label_heights[li])return unsupported("if stack height is unavailable");if(!matching_suffix(stack,labels[li].result_types))return unsupported("if then arm result types mismatch");stack.resize(*label_heights[li]);stack.insert(stack.end(),labels[li].result_types.begin(),labels[li].result_types.end());continue;}
            if(op==0x0b){if(end_label[n]){const auto li=*end_label[n];if(!label_heights[li]||!matching_suffix(stack,labels[li].result_types))return unsupported("block end result types mismatch");stack.resize(*label_heights[li]);stack.insert(stack.end(),labels[li].result_types.begin(),labels[li].result_types.end());if(!end_shapes[li]||*end_shapes[li]!=stack)return unsupported("block end has an incompatible operand stack");}else if(n==function_end){auto result=signature_results();if(!result)return result.error();if(stack!=result.value())return unsupported("function end result stack does not match its signature");}continue;}
            if(op==0x0f){auto result=signature_results();if(!result)return result.error();if(!matching_suffix(stack,result.value()))return unsupported("return stack does not match the function result types");continue;}
            if(op==0x00)break;
            if(op==0x1a){auto v=shape_pop(stack,{});if(!v)return v.error();continue;}
            if(op==0x1b){auto c=shape_pop(stack,integer(32));if(!c)return c.error();auto a=shape_pop(stack,{});if(!a)return a.error();auto b=shape_pop(stack,a.value());if(!b)return b.error();stack.push_back(a.value());continue;}
            if(op==0x1c){const auto type_code=immediate(code[n]->instruction);if(!type_code||*type_code>UINT8_MAX)return unsupported("typed select result type unavailable");const auto type=wasm_value_type(static_cast<std::uint8_t>(*type_code));if(!type)return unsupported("typed select result type is unsupported");auto c=shape_pop(stack,integer(32));if(!c)return c.error();auto a=shape_pop(stack,*type);if(!a)return a.error();auto b=shape_pop(stack,*type);if(!b)return b.error();stack.push_back(*type);continue;}
            if(op==0x0c||op==0x0d){if(op==0x0d){auto c=shape_pop(stack,integer(32));if(!c)return c.error();}continue;}
            if(op==0x0e){auto c=shape_pop(stack,integer(32));if(!c)return c.error();continue;}
            if (op >= 0x20 && op <= 0x22) {
                const auto index = immediate(code[n]->instruction);
                const auto type = index ? local_type(*index) : std::optional<ValueType>{};
                if (!index || !type)
                    return unsupported("local index is outside the typed parameter/local declarations");
                if (op == 0x20) stack.push_back(*type);
                else {
                    auto value = shape_pop(stack, *type);
                    if (!value) return value.error();
                    if (op == 0x22) stack.push_back(value.value());
                }
                continue;
            }
            if (op == 0x23 || op == 0x24) {
                const auto index = immediate(code[n]->instruction);
                if (!metadata || metadata->globals.size() !=
                        static_cast<std::uint64_t>(metadata->imported_globals) + metadata->defined_globals ||
                    !index || *index >= metadata->globals.size())
                    return unsupported("global index or exact type metadata is unavailable");
                const auto &global = metadata->globals[static_cast<std::size_t>(*index)];
                const auto type = wasm_value_type(global.value_type);
                if (!type) return unsupported("global value type is not a supported numeric MVP type");
                if (op == 0x24 && !global.mutable_value)
                    return unsupported("global.set targets an immutable global");
                if (op == 0x23) stack.push_back(*type);
                else { auto value = shape_pop(stack, *type); if (!value) return value.error(); }
                continue;
            }
            if (op == 0x10) {
                const auto index = immediate(code[n]->instruction);
                const auto *callee = index ? signature_for(*index) : nullptr;
                if (!callee || callee->parameter_count != callee->parameter_types.size() ||
                    callee->result_count != callee->result_types.size())
                    return unsupported("direct call target or function signature metadata is unavailable");
                if (callee->parameter_types.size() > max_stack || callee->result_types.size() > max_stack)
                    return Error{ErrorCode::resource_limit, "direct call exceeds the 128-value parameter/result bound"};
                for (auto it = callee->parameter_types.rbegin(); it != callee->parameter_types.rend(); ++it) {
                    const auto type = wasm_value_type(*it);
                    if (!type) return unsupported("direct call parameter type is unsupported");
                    auto argument = shape_pop(stack, *type);
                    if (!argument) return argument.error();
                }
                for (const auto result : callee->result_types) {
                    const auto type = wasm_value_type(result);
                    if (!type) return unsupported("direct call result type is unsupported");
                    stack.push_back(*type);
                }
                continue;
            }
            if (op == 0x11) {
                const auto type_index = immediate(code[n]->instruction, 0);
                if (!metadata || !type_index || *type_index >= metadata->function_types.size())
                    return unsupported("call_indirect type metadata is unavailable");
                const auto &callee = metadata->function_types[*type_index];
                if (callee.parameter_count != callee.parameter_types.size() || callee.result_count != callee.result_types.size() ||
                    callee.parameter_types.size() > 127 || callee.result_types.size() > max_stack)
                    return Error{ErrorCode::resource_limit, "call_indirect exceeds the 127-parameter or 128-result bound"};
                auto table_slot = shape_pop(stack, integer(32));
                if (!table_slot) return table_slot.error();
                for (auto it = callee.parameter_types.rbegin(); it != callee.parameter_types.rend(); ++it) {
                    auto type = wasm_value_type(*it);
                    if (!type) return unsupported("call_indirect parameter type is unsupported");
                    auto argument = shape_pop(stack, *type);
                    if (!argument) return argument.error();
                }
                for (const auto result : callee.result_types) {
                    auto type = wasm_value_type(result);
                    if (!type) return unsupported("call_indirect result type is unsupported");
                    stack.push_back(*type);
                }
                continue;
            }
            if (op >= 0x28 && op <= 0x3e) {
                const auto info = memory_op(op);
                if (!info) return unsupported("memory opcode metadata is unavailable");
                auto args = memory_immediates(code[n]->instruction, *info, metadata);
                if (!args) return args.error();
                if (info->store) {
                    auto value = shape_pop(stack, info->stack_type);
                    if (!value) return value.error();
                    auto address = shape_pop(stack, integer(32));
                    if (!address) return address.error();
                } else {
                    auto address = shape_pop(stack, integer(32));
                    if (!address) return address.error();
                    stack.push_back(info->stack_type);
                }
                continue;
            }
            if (op == 0xfd) {
                const auto subopcode = simd_subopcode(code[n]->instruction);
                const auto relaxed = subopcode ? simd_relaxed_op(*subopcode) : std::optional<SimdRelaxedOpInfo>{};
                if (relaxed) {
                    const auto &instruction = code[n]->instruction;
                    if (!instruction.operands.empty() || instruction.mnemonic_override != relaxed->name)
                        return unsupported("relaxed SIMD opcode metadata is inconsistent");
                    for (unsigned operand = 0; operand < relaxed->input_count; ++operand) {
                        auto value = shape_pop(stack, vector(128));
                        if (!value) return value.error();
                    }
                    stack.push_back(vector(128));
                    continue;
                }
                const auto float_unary = subopcode ? simd_float_unary(*subopcode) : std::optional<std::string_view>{};
                if (float_unary) {
                    const auto &instruction = code[n]->instruction;
                    if (!instruction.operands.empty() || instruction.mnemonic_override != *float_unary)
                        return unsupported("SIMD floating unary opcode metadata is inconsistent");
                    auto value = shape_pop(stack, vector(128));
                    if (!value) return value.error();
                    stack.push_back(vector(128));
                    continue;
                }
                const auto float_binary = subopcode ? simd_float_binary(*subopcode) : std::optional<std::string_view>{};
                if (float_binary) {
                    const auto &instruction = code[n]->instruction;
                    if (!instruction.operands.empty() || instruction.mnemonic_override != *float_binary)
                        return unsupported("SIMD floating binary opcode metadata is inconsistent");
                    auto right = shape_pop(stack, vector(128));
                    auto left = shape_pop(stack, vector(128));
                    if (!right) return right.error();
                    if (!left) return left.error();
                    stack.push_back(vector(128));
                    continue;
                }
                const auto conversion = subopcode ? simd_conversion(*subopcode) : std::optional<std::string_view>{};
                if (conversion) {
                    const auto &instruction = code[n]->instruction;
                    if (!instruction.operands.empty() || instruction.mnemonic_override != *conversion)
                        return unsupported("SIMD conversion opcode metadata is inconsistent");
                    auto value = shape_pop(stack, vector(128));
                    if (!value) return value.error();
                    stack.push_back(vector(128));
                    continue;
                }
                if (subopcode && *subopcode == 13) {
                    // wasm.cpp decodes each of the sixteen shuffle bytes as
                    // an 8-bit unsigned immediate and rejects values >= 32.
                    // Recheck the shape here so malformed synthetic
                    // Instruction records fail closed before lifting.
                    const auto &instruction = code[n]->instruction;
                    if (instruction.operands.size() != 16)
                        return unsupported("SIMD shuffle requires exactly sixteen lane selectors");
                    for (std::size_t lane = 0; lane < instruction.operands.size(); ++lane) {
                        const auto selected = immediate(instruction, lane);
                        if (!selected || *selected >= 32)
                            return unsupported("SIMD shuffle selector is missing or outside the two input vectors");
                    }
                    auto second = shape_pop(stack, vector(128));
                    auto first = shape_pop(stack, vector(128));
                    if (!second) return second.error();
                    if (!first) return first.error();
                    stack.push_back(vector(128));
                    continue;
                }
                if (subopcode && *subopcode == 14) {
                    auto indices = shape_pop(stack, vector(128));
                    auto source = shape_pop(stack, vector(128));
                    if (!indices) return indices.error();
                    if (!source) return source.error();
                    stack.push_back(vector(128));
                    continue;
                }
                const auto integer_unary = subopcode ? simd_integer_unary(*subopcode) : std::optional<SimdIntegerUnaryInfo>{};
                if (integer_unary) {
                    auto value = shape_pop(stack, vector(128));
                    if (!value) return value.error();
                    stack.push_back(integer_unary->result_type);
                    continue;
                }
                const auto splat = subopcode ? simd_splat_op(*subopcode) : std::optional<SimdSplatOpInfo>{};
                if (splat) {
                    auto scalar = shape_pop(stack, splat->scalar_type);
                    if (!scalar) return scalar.error();
                    stack.push_back(vector(128));
                    continue;
                }
                const auto lane = subopcode ? simd_lane_op(*subopcode) : std::optional<SimdLaneOpInfo>{};
                if (lane) {
                    const auto lane_index = immediate(code[n]->instruction, 0);
                    if (!lane_index || *lane_index >= lane->lane_count)
                        return unsupported("SIMD lane immediate is missing or outside its lane count");
                    if (lane->replace) {
                        auto scalar = shape_pop(stack, lane->scalar_type);
                        if (!scalar) return scalar.error();
                        auto value = shape_pop(stack, vector(128));
                        if (!value) return value.error();
                        stack.push_back(vector(128));
                    } else {
                        auto value = shape_pop(stack, vector(128));
                        if (!value) return value.error();
                        stack.push_back(lane->scalar_type);
                    }
                    continue;
                }
                if (subopcode && (*subopcode == 77 || (*subopcode >= 78 && *subopcode <= 83))) {
                    const auto vector_type = vector(128);
                    const unsigned inputs = *subopcode == 82 ? 3 :
                        (*subopcode == 77 || *subopcode == 83 ? 1 : 2);
                    for (unsigned operand_index = 0; operand_index < inputs; ++operand_index) {
                        auto value = shape_pop(stack, vector_type);
                        if (!value) return value.error();
                    }
                    stack.push_back(*subopcode == 83 ? integer(32) : vector_type);
                    continue;
                }
                if (subopcode && ((*subopcode >= 0x23 && *subopcode <= 0x4c) ||
                                  (*subopcode >= 0xd6 && *subopcode <= 0xdb))) {
                    auto right = shape_pop(stack, vector(128));
                    auto left = shape_pop(stack, vector(128));
                    if (!right) return right.error();
                    if (!left) return left.error();
                    stack.push_back(vector(128));
                    continue;
                }
                const auto extmul = subopcode ? simd_integer_extmul(*subopcode) : std::optional<std::string_view>{};
                if (extmul) {
                    const auto &instruction = code[n]->instruction;
                    if (!instruction.operands.empty() || instruction.mnemonic_override != *extmul)
                        return unsupported("SIMD extended-multiply opcode metadata is inconsistent");
                    auto right = shape_pop(stack, vector(128));
                    auto left = shape_pop(stack, vector(128));
                    if (!right) return right.error();
                    if (!left) return left.error();
                    stack.push_back(vector(128));
                    continue;
                }
                if (subopcode && wasm_simd_integer_binary_op(*subopcode)) {
                    auto right = shape_pop(stack, vector(128));
                    auto left = shape_pop(stack, vector(128));
                    if (!right) return right.error();
                    if (!left) return left.error();
                    stack.push_back(vector(128));
                    continue;
                }
                if (subopcode && simd_integer_shift(*subopcode)) {
                    auto shift = shape_pop(stack, integer(32));
                    if (!shift) return shift.error();
                    auto value = shape_pop(stack, vector(128));
                    if (!value) return value.error();
                    stack.push_back(vector(128));
                    continue;
                }
                if (subopcode && simd_integer_extend_or_pairwise_add(*subopcode)) {
                    auto value = shape_pop(stack, vector(128));
                    if (!value) return value.error();
                    stack.push_back(vector(128));
                    continue;
                }
                if (subopcode && simd_integer_narrow(*subopcode)) {
                    auto high = shape_pop(stack, vector(128));
                    auto low = shape_pop(stack, vector(128));
                    if (!high) return high.error();
                    if (!low) return low.error();
                    stack.push_back(vector(128));
                    continue;
                }
                const auto info = subopcode ? simd_memory_op(*subopcode) : std::optional<SimdMemoryOpInfo>{};
                if (!info) return unsupported("SIMD instruction is outside the supported memory subset");
                if (!metadata || static_cast<std::uint64_t>(metadata->imported_memories) + metadata->defined_memories != 1)
                    return unsupported("SIMD memory operation requires exactly one validated module memory");
                const auto alignment = immediate(code[n]->instruction, 0);
                const auto offset = immediate(code[n]->instruction, 1);
                const auto expected_operands = info->lane_indexed ? 3u : 2u;
                if (code[n]->instruction.operands.size() != expected_operands || !alignment || !offset)
                    return unsupported("SIMD memory alignment or offset immediate unavailable");
                if (*alignment > info->maximum_alignment_exponent || *offset > UINT32_MAX)
                    return unsupported("SIMD memory alignment or Wasm32 offset exceeds its supported bound");
                if (info->lane_indexed) {
                    const auto lane = immediate(code[n]->instruction, 2);
                    const auto lane_count = 128u / info->access_bits;
                    if (code[n]->instruction.operands.size() != 3 || !lane || *lane >= lane_count)
                        return unsupported("SIMD lane memory operation has a missing or out-of-range lane index");
                    auto value = shape_pop(stack, vector(128));
                    auto address = shape_pop(stack, integer(32));
                    if (!value) return value.error();
                    if (!address) return address.error();
                    if (!info->store) stack.push_back(vector(128));
                    continue;
                }
                if (info->store) {
                    auto value = shape_pop(stack, info->stack_type);
                    if (!value) return value.error();
                    auto address = shape_pop(stack, integer(32));
                    if (!address) return address.error();
                } else {
                    auto address = shape_pop(stack, integer(32));
                    if (!address) return address.error();
                    stack.push_back(info->stack_type);
                }
                continue;
            }
            if (op == 0x3f || op == 0x40) {
                const auto memory_index = immediate(code[n]->instruction);
                if (!metadata ||
                    static_cast<std::uint64_t>(metadata->imported_memories) + metadata->defined_memories != 1 ||
                    !memory_index || *memory_index != 0)
                    return unsupported("memory.size/grow requires one validated memory at index zero");
                if (op == 0x40) {
                    auto delta = shape_pop(stack, integer(32));
                    if (!delta) return delta.error();
                }
                stack.push_back(integer(32));
                continue;
            }
            if (op == 0xfc) {
                const auto subopcode = bulk_memory_subopcode(code[n]->instruction);
                if (!subopcode || !valid_bulk_memory_indices(code[n]->instruction, metadata, *subopcode))
                    return unsupported("bulk-memory instruction requires validated segment and single-memory indices");
                if (*subopcode <= 7) {
                    const auto cv = saturating_conversion(*subopcode);
                    if (!cv) return unsupported("trunc_sat subopcode is unavailable");
                    auto value = shape_pop(stack, cv->input);
                    if (!value) return value.error();
                    stack.push_back(cv->output);
                } else if (*subopcode == 8 || *subopcode == 10 || *subopcode == 11 ||
                           *subopcode == 12 || *subopcode == 14 || *subopcode == 17) {
                    for (unsigned operand = 0; operand < 3; ++operand) {
                        const bool reference_value = *subopcode == 17 && operand == 1;
                        auto value = shape_pop(stack, reference_value ? funcref() : integer(32));
                        if (!value) return value.error();
                    }
                } else if (*subopcode == 15) {
                    auto delta = shape_pop(stack, integer(32));
                    if (!delta) return delta.error();
                    auto reference = shape_pop(stack, funcref());
                    if (!reference) return reference.error();
                    stack.push_back(integer(32));
                } else if (*subopcode == 16) {
                    stack.push_back(integer(32));
                }
                continue;
            }
            if(op==0xd0||op==0xd2){stack.push_back(funcref());}
            else if(op==0xd1){auto v=shape_pop(stack,funcref());if(!v)return v.error();stack.push_back(integer(32));}
            else if(op==0x41||op==0x42||op==0x43||op==0x44){stack.push_back(op==0x41?integer(32):op==0x42?integer(64):op==0x43?floating(32):floating(64));}
            else if(auto info=numeric(op)){for(unsigned p=0;p<info->pops;++p){auto v=shape_pop(stack,info->input);if(!v)return v.error();}stack.push_back(info->output);}
            else if(auto cv=conversion(op)){auto v=shape_pop(stack,cv->input);if(!v)return v.error();stack.push_back(cv->output);}
            else if(auto ext=sign_extension(op)){auto v=shape_pop(stack,ext->type);if(!v)return v.error();stack.push_back(ext->type);}
            else if(op>=0xa7&&op<=0xbf)return unsupported("numeric conversion or reinterpret opcode is not modeled");
            else return unsupported("opcode/effect is not in the typed scalar subset: "+code[n]->instruction.mnemonic_override);
            if(stack.size()>max_stack)return Error{ErrorCode::resource_limit,"WebAssembly operand stack exceeds 128 values"};
        }
        exits[bi]=stack;
        for(auto &edge:successors[bi]){
            Shape edge_shape=stack;
            std::vector<std::size_t> source_slots(stack.size());
            for (std::size_t slot = 0; slot < source_slots.size(); ++slot) source_slots[slot] = slot;
            if(edge.label){const auto li=*edge.label;if(!branch_shapes[li]||!label_heights[li])return unsupported("branch reaches a label before its stack shape is known");const auto &types=labels[li].kind==3?labels[li].parameters:labels[li].result_types;if(!matching_suffix(edge_shape,types)||edge_shape.size()<*label_heights[li]+types.size())return unsupported("branch values do not match target label types");
                const auto value_base = edge_shape.size() - types.size();
                edge_shape.resize(*label_heights[li]);
                source_slots.resize(*label_heights[li]);
                edge_shape.insert(edge_shape.end(), types.begin(), types.end());
                for (std::size_t value = 0; value < types.size(); ++value)
                    source_slots.push_back(value_base + value);
                if(*branch_shapes[li]!=edge_shape)return unsupported("branch stack prefix disagrees at its target");
            }
            if (source_slots.size() != edge_shape.size())
                return Error{ErrorCode::malformed, "WebAssembly edge stack projection has an inconsistent height"};
            if (!edge.bridge) {
                auto &maps = incoming_slot_sources[edge.target];
                const auto map_it = maps.find(bi);
                if (map_it == maps.end()) {
                    maps.emplace(bi, source_slots);
                    auto &inputs = predecessors[edge.target];
                    if (std::find(inputs.begin(), inputs.end(), bi) == inputs.end()) inputs.push_back(bi);
                } else if (map_it->second != source_slots) {
                    if (starts.size() + edge_bridges.size() >= max_blocks)
                        return Error{ErrorCode::resource_limit, "WebAssembly edge bridges exceed the block limit"};
                    const auto bridge = starts.size() + edge_bridges.size();
                    edge.bridge = bridge;
                    edge_bridges.push_back({bi, edge.target, edge.kind,
                        code[finish - 1]->instruction.address, source_slots});
                    entries.resize(bridge + 1);
                    exits.resize(bridge + 1);
                    predecessors.resize(bridge + 1);
                    incoming_slot_sources.resize(bridge + 1);
                    queued.resize(bridge + 1);
                    entries[bridge] = edge_shape;
                    exits[bridge] = edge_shape;
                    predecessors[bridge].push_back(bi);
                    incoming_slot_sources[bridge].emplace(bi, source_slots);
                    std::vector<std::size_t> identity(edge_shape.size());
                    for (std::size_t slot = 0; slot < identity.size(); ++slot) identity[slot] = slot;
                    incoming_slot_sources[edge.target].emplace(bridge, std::move(identity));
                    auto &inputs = predecessors[edge.target];
                    if (std::find(inputs.begin(), inputs.end(), bridge) == inputs.end()) inputs.push_back(bridge);
                }
            }
            if(!entries[edge.target]){entries[edge.target]=edge_shape;if(!queued[edge.target]){work.push_back(edge.target);queued[edge.target]=true;}}
            else if(*entries[edge.target]!=edge_shape)return unsupported("operand stack shapes disagree at a control-flow join");
        }
    }

    // Track exact reference nullness through locals and globals. The operand-
    // stack fact is intentionally limited to values produced by ref.null/
    // ref.func, local/global.get, carried through local/global.set/tee, or
    // immediately consumed by ref.is_null. Other stack effects reset it.
    std::vector<ReferenceNullness> ref_is_null_input(code.size(), ReferenceNullness::unknown);
    std::vector<std::optional<std::vector<ReferenceNullness>>> local_nullness_entries(starts.size());
    std::vector<bool> nullness_queued(starts.size());
    struct NullBranchPredicate {
        std::size_t reference_slot;
        bool true_edge_is_null;
        bool operator==(const NullBranchPredicate &) const = default;
    };
    struct NullnessStackFact {
        ReferenceNullness reference = ReferenceNullness::unknown;
        std::optional<std::size_t> origin;
        std::optional<bool> integer_nonzero;
    };
    std::vector<std::optional<NullBranchPredicate>> branch_predicate_entries(starts.size());
    std::vector<bool> branch_predicate_seen(starts.size());
    const auto global_count = metadata ? metadata->globals.size() : 0;
    if (!starts.empty() && (!local_types.empty() || global_count != 0) && entries[0]) {
        const auto parameter_count = function_signature ? function_signature->parameter_types.size() : 0;
        std::vector<ReferenceNullness> initial(local_types.size() + global_count, ReferenceNullness::unknown);
        for (std::size_t index = parameter_count; index < local_types.size(); ++index)
            if (local_types[index].kind == TypeKind::pointer)
                initial[index] = ReferenceNullness::null_value;
        // Immutable function-reference globals have a stable module value.
        // Mutable globals start unknown because another invocation may have
        // changed them before this function is analyzed or called.
        if (metadata && metadata->globals.size() ==
                static_cast<std::uint64_t>(metadata->imported_globals) + metadata->defined_globals) {
            for (std::size_t index = 0; index < global_count; ++index) {
                const auto &global = metadata->globals[index];
                if ((global.value_type != 0x70 && global.value_type != 0x6f) ||
                    global.mutable_value || !global.initializer) continue;
                if (global.initializer->kind == WasmGlobalInitializerKind::ref_null)
                    initial[local_types.size() + index] = ReferenceNullness::null_value;
                else if (global.initializer->kind == WasmGlobalInitializerKind::ref_func)
                    initial[local_types.size() + index] = ReferenceNullness::non_null;
            }
        }
        local_nullness_entries[0] = std::move(initial);
        branch_predicate_seen[0] = true;
        std::deque<std::size_t> work{0};
        nullness_queued[0] = true;
        std::size_t visited_instructions = 0;
        constexpr std::size_t max_nullness_work = 4'000'000;
        bool exceeded_work = false;
        while (!work.empty()) {
            const auto bi = work.front();
            work.pop_front();
            nullness_queued[bi] = false;
            if (!local_nullness_entries[bi] || !entries[bi]) continue;
            auto locals = *local_nullness_entries[bi];
            auto top = ReferenceNullness::unknown;
            auto branch_predicate = branch_predicate_entries[bi];
            // Track only a directly identifiable local/global reference. This
            // lets a ref.is_null condition refine the two outgoing paths of
            // br_if/if without pretending that arbitrary stack expressions
            // have stable identity.
            std::optional<std::size_t> top_reference_origin;
            // Keep a small abstract operand stack for the reference/nullness
            // operations whose effects are modeled below. At block entry,
            // stack values arrive through predecessor phis, so their facts
            // are unknown until a local or constant establishes one.
            std::vector<NullnessStackFact> stack_facts(entries[bi]->size());
            bool stack_facts_valid = true;
            const auto push_stack_fact = [&](NullnessStackFact fact) {
                if (stack_facts_valid) stack_facts.push_back(std::move(fact));
            };
            const auto pop_stack_fact = [&]() -> std::optional<NullnessStackFact> {
                if (!stack_facts_valid || stack_facts.empty()) return {};
                auto fact = stack_facts.back();
                stack_facts.pop_back();
                return fact;
            };
            const auto invalidate_stack_facts = [&]() {
                stack_facts_valid = false;
                stack_facts.clear();
            };
            const auto begin = starts[bi];
            const auto finish = bi + 1 < starts.size() ? starts[bi + 1] : code.size();
            for (std::size_t n = begin; n < finish; ++n) {
                if (++visited_instructions > max_nullness_work) {
                    exceeded_work = true;
                    break;
                }
                const auto &instruction = code[n]->instruction;
                const auto op = std::to_integer<std::uint8_t>(instruction.bytes[0]);
                if (op != 0x01 && op != 0x0d && op != 0x04 && op != 0x45)
                    branch_predicate.reset();
                if (op == 0xd0) {
                    top = ReferenceNullness::null_value;
                    top_reference_origin.reset();
                    push_stack_fact({ReferenceNullness::null_value, {}, {}});
                } else if (op == 0xd2) {
                    top = ReferenceNullness::non_null;
                    top_reference_origin.reset();
                    push_stack_fact({ReferenceNullness::non_null, {}, {}});
                } else if (op == 0x20 || op == 0x21 || op == 0x22) {
                    const auto index = immediate(instruction);
                    const auto type = index ? local_type(*index) : std::optional<ValueType>{};
                    if (!index || !type || *index >= locals.size()) {
                        top = ReferenceNullness::unknown;
                        top_reference_origin.reset();
                        continue;
                    }
                    if (op == 0x20) {
                        top = type->kind == TypeKind::pointer
                            ? locals[static_cast<std::size_t>(*index)] : ReferenceNullness::unknown;
                        if (type->kind == TypeKind::pointer)
                            top_reference_origin = static_cast<std::size_t>(*index);
                        else
                            top_reference_origin.reset();
                        push_stack_fact({top, top_reference_origin, {}});
                    } else {
                        const auto assigned_fact = pop_stack_fact();
                        if (type->kind == TypeKind::pointer)
                            locals[static_cast<std::size_t>(*index)] = assigned_fact
                                ? assigned_fact->reference : top;
                        else
                            locals[static_cast<std::size_t>(*index)] = ReferenceNullness::unknown;
                        if (op == 0x21) {
                            top = ReferenceNullness::unknown;
                            top_reference_origin.reset();
                        } else if (type->kind == TypeKind::pointer) {
                            top_reference_origin = static_cast<std::size_t>(*index);
                            if (assigned_fact) {
                                auto tee_fact = *assigned_fact;
                                tee_fact.origin = top_reference_origin;
                                tee_fact.reference = locals[static_cast<std::size_t>(*index)];
                                push_stack_fact(std::move(tee_fact));
                            }
                        }
                    }
                } else if (op == 0x23 || op == 0x24) {
                    const auto index = immediate(instruction);
                    if (!index || !metadata || *index >= metadata->globals.size()) {
                        top = ReferenceNullness::unknown;
                        top_reference_origin.reset();
                        continue;
                    }
                    const auto global_index = static_cast<std::size_t>(*index);
                    const auto &global = metadata->globals[global_index];
                    if (global.value_type != 0x70 && global.value_type != 0x6f) {
                        top = ReferenceNullness::unknown;
                        top_reference_origin.reset();
                        if (op == 0x23) push_stack_fact({});
                        else if (!pop_stack_fact()) invalidate_stack_facts();
                    } else if (op == 0x23) {
                        const auto slot = local_types.size() + global_index;
                        top = locals[slot];
                        top_reference_origin = slot;
                        push_stack_fact({top, top_reference_origin, {}});
                    } else {
                        const auto assigned_fact = pop_stack_fact();
                        if (global.mutable_value)
                            locals[local_types.size() + global_index] = assigned_fact
                                ? assigned_fact->reference : top;
                        top = ReferenceNullness::unknown;
                        top_reference_origin.reset();
                    }
                } else if (op == 0xd1) {
                    const auto tested_fact = pop_stack_fact();
                    ref_is_null_input[n] = tested_fact ? tested_fact->reference : top;
                    const auto origin = tested_fact ? tested_fact->origin : top_reference_origin;
                    if (origin)
                        branch_predicate = NullBranchPredicate{*origin, true};
                    else
                        branch_predicate.reset();
                    const auto known = ref_is_null_input[n];
                    push_stack_fact({ReferenceNullness::unknown, {},
                        known == ReferenceNullness::null_value ? std::optional<bool>{true}
                      : known == ReferenceNullness::non_null ? std::optional<bool>{false}
                                                             : std::optional<bool>{}});
                    top = ReferenceNullness::unknown;
                    top_reference_origin.reset();
                } else if (op == 0x45) {
                    auto tested_fact = pop_stack_fact();
                    // i32.eqz reverses a directly produced ref.is_null result:
                    // the true edge now means the reference is non-null.
                    if (branch_predicate)
                        branch_predicate->true_edge_is_null = !branch_predicate->true_edge_is_null;
                    if (tested_fact && tested_fact->integer_nonzero)
                        tested_fact->integer_nonzero = !*tested_fact->integer_nonzero;
                    push_stack_fact({ReferenceNullness::unknown, {},
                        tested_fact ? tested_fact->integer_nonzero : std::optional<bool>{}});
                    top = ReferenceNullness::unknown;
                    top_reference_origin.reset();
                } else if (op == 0x41) {
                    const auto value = immediate(instruction);
                    push_stack_fact({ReferenceNullness::unknown, {},
                        value ? std::optional<bool>{*value != 0} : std::optional<bool>{}});
                    top = ReferenceNullness::unknown;
                    top_reference_origin.reset();
                } else if (op == 0x1b || op == 0x1c) {
                    const auto condition = pop_stack_fact();
                    const auto when_true = pop_stack_fact();
                    const auto when_false = pop_stack_fact();
                    if (condition && when_true && when_false) {
                        NullnessStackFact selected;
                        if (condition->integer_nonzero)
                            selected = *condition->integer_nonzero ? *when_true : *when_false;
                        else if (when_true->reference == when_false->reference)
                            selected.reference = when_true->reference;
                        if (when_true->origin == when_false->origin)
                            selected.origin = when_true->origin;
                        push_stack_fact(selected);
                        top = selected.reference;
                        top_reference_origin = selected.origin;
                    } else {
                        invalidate_stack_facts();
                        top = ReferenceNullness::unknown;
                        top_reference_origin.reset();
                    }
                } else if (op == 0x1a) {
                    if (!pop_stack_fact()) invalidate_stack_facts();
                    top = ReferenceNullness::unknown;
                    top_reference_origin.reset();
                } else if (op == 0x0d || op == 0x04) {
                    // The condition is consumed here. Keep only the narrow
                    // ref.is_null provenance for the edge transfer below.
                    if (!pop_stack_fact()) invalidate_stack_facts();
                } else if (op != 0x01) {
                    invalidate_stack_facts();
                    if (op == 0x10 || op == 0x11) {
                        // Calls can mutate any mutable global through direct,
                        // imported, or table-dispatched code.
                        if (metadata)
                            for (std::size_t index = 0; index < global_count; ++index)
                                if (metadata->globals[index].mutable_value)
                                    locals[local_types.size() + index] = ReferenceNullness::unknown;
                    }
                    top = ReferenceNullness::unknown;
                    top_reference_origin.reset();
                    branch_predicate.reset();
                }
            }
            if (exceeded_work) break;
            const auto terminator = finish > begin
                ? std::to_integer<std::uint8_t>(code[finish - 1]->instruction.bytes[0]) : 0;
            const bool ref_null_branch = branch_predicate &&
                (terminator == 0x0d || terminator == 0x04);
            const auto successor_predicate = (terminator == 0x0d || terminator == 0x04)
                ? std::optional<NullBranchPredicate>{}
                : branch_predicate;
            for (const auto &edge : successors[bi]) {
                const auto target = edge.target;
                if (target >= starts.size() || !entries[target]) continue;
                auto edge_locals = locals;
                if (ref_null_branch &&
                    (edge.kind == BlockEdgeKind::conditional_true ||
                     edge.kind == BlockEdgeKind::conditional_false) &&
                    branch_predicate->reference_slot < edge_locals.size()) {
                    const bool true_edge = edge.kind == BlockEdgeKind::conditional_true;
                    const bool is_null = true_edge == branch_predicate->true_edge_is_null;
                    edge_locals[branch_predicate->reference_slot] = is_null
                        ? ReferenceNullness::null_value : ReferenceNullness::non_null;
                }
                bool changed = false;
                if (!branch_predicate_seen[target]) {
                    branch_predicate_entries[target] = successor_predicate;
                    branch_predicate_seen[target] = true;
                    changed = successor_predicate.has_value();
                } else if (branch_predicate_entries[target] &&
                           branch_predicate_entries[target] != successor_predicate) {
                    branch_predicate_entries[target].reset();
                    changed = true;
                }
                if (!local_nullness_entries[target]) {
                    local_nullness_entries[target] = std::move(edge_locals);
                    changed = true;
                } else {
                    auto &incoming = *local_nullness_entries[target];
                    for (std::size_t index = 0; index < incoming.size(); ++index) {
                        if (incoming[index] != edge_locals[index] && incoming[index] != ReferenceNullness::unknown) {
                            incoming[index] = ReferenceNullness::unknown;
                            changed = true;
                        }
                    }
                }
                if (changed && !nullness_queued[target]) {
                    work.push_back(target);
                    nullness_queued[target] = true;
                }
            }
        }
        if (exceeded_work)
            std::fill(ref_is_null_input.begin(), ref_is_null_input.end(), ReferenceNullness::unknown);
    }

    auto function_result_types = signature_results();
    if (!function_result_types) return function_result_types.error();
    LiftedFunction out{function.id,function.entry,{},{}};
    const auto total_blocks = starts.size() + edge_bridges.size();
    std::vector<std::vector<std::uint32_t>> output_versions(total_blocks),phi_versions(total_blocks);
    std::array<std::uint32_t,256> versions{};
    for(std::size_t bi=0;bi<total_blocks;++bi)if(entries[bi]){
        if(exits[bi]&&(!successors[bi].empty()||bi>=starts.size())){output_versions[bi].resize(exits[bi]->size());for(std::size_t slot=0;slot<exits[bi]->size();++slot)output_versions[bi][slot]=++versions[slot];}
        if(predecessors[bi].size()>1){phi_versions[bi].resize(entries[bi]->size());for(std::size_t slot=0;slot<entries[bi]->size();++slot)phi_versions[bi][slot]=++versions[slot];}
    }
    const auto bridge_id = [&](std::size_t index) {
        return BlockId{0x8000000000000000ULL + index - starts.size() + 1};
    };
    const auto bridge_address = [&](std::size_t index) {
        return Address{{UINT32_MAX}, static_cast<std::uint64_t>(index - starts.size()) + 1};
    };
    const auto route_address = [&](std::size_t source, std::size_t target,
                                   std::optional<std::size_t> label, BlockEdgeKind kind) {
        for (const auto &edge : successors[source])
            if (edge.target == target && edge.label == label && edge.kind == kind)
                return edge.bridge ? bridge_address(*edge.bridge)
                                    : code[starts[target]]->instruction.address;
        return code[starts[target]]->instruction.address;
    };
    for(std::size_t bi=0;bi<starts.size();++bi)if(entries[bi]){
        const auto begin=starts[bi],finish=bi+1<starts.size()?starts[bi+1]:code.size(),last=finish-1;
        const BlockId id{static_cast<std::uint64_t>(bi+1)};
        LiftedBlock lifted{id,code[begin]->instruction.address,{},{}};
        for(const auto &edge:successors[bi]){
            const auto target_addr=edge.bridge?bridge_address(*edge.bridge):code[starts[edge.target]]->instruction.address;
            const auto target_id=edge.bridge?bridge_id(*edge.bridge):BlockId{static_cast<std::uint64_t>(edge.target+1)};
            lifted.successors.push_back({code[last]->instruction.address,target_addr,target_id,edge.kind});
        }
        for(std::size_t n=begin;n<finish;++n){
            const auto op=std::to_integer<std::uint8_t>(code[n]->instruction.bytes[0]);
            if(op==0x00)
                lifted.trap_edges.push_back({code[n]->instruction.address,TrapEdgeKind::unconditional,"unreachable"});
            if(op==0x00)break;
        }
        for(std::size_t slot=0;slot<phi_versions[bi].size();++slot){const RegisterOperand reg{RegisterBank::wasm_stack,static_cast<std::uint8_t>(slot),entries[bi]->at(slot).bits,false};LiftedBlock::Phi phi{reg,phi_versions[bi][slot],{}};for(const auto pred:predecessors[bi]){const auto projection=incoming_slot_sources[bi].find(pred);if(projection==incoming_slot_sources[bi].end()||slot>=projection->second.size())return Error{ErrorCode::malformed,"WebAssembly predecessor stack projection is unavailable"};const auto source_slot=projection->second[slot];if(source_slot>=output_versions[pred].size())return Error{ErrorCode::malformed,"WebAssembly predecessor has no stack value for join"};phi.inputs.push_back({pred>=starts.size()?bridge_id(pred):BlockId{static_cast<std::uint64_t>(pred+1)},output_versions[pred][source_slot]});}lifted.phis.push_back(std::move(phi));}
        Stack stack;
        if(!predecessors[bi].empty())for(std::size_t slot=0;slot<entries[bi]->size();++slot){const RegisterOperand reg{RegisterBank::wasm_stack,static_cast<std::uint8_t>(slot),entries[bi]->at(slot).bits,false};if(predecessors[bi].size()>1)stack.push_back(std::make_shared<Expression>(Expression{entries[bi]->at(slot),RegisterValue{reg,phi_versions[bi][slot]}}));else{const auto pred=predecessors[bi].front();const auto projection=incoming_slot_sources[bi].find(pred);if(projection==incoming_slot_sources[bi].end()||slot>=projection->second.size())return Error{ErrorCode::malformed,"WebAssembly predecessor stack projection is unavailable"};const auto source_slot=projection->second[slot];if(source_slot>=output_versions[pred].size())return Error{ErrorCode::malformed,"WebAssembly predecessor stack value is unavailable"};stack.push_back(std::make_shared<Expression>(Expression{entries[bi]->at(slot),RegisterValue{reg,output_versions[pred][source_slot]}}));}}
        auto pop=[&](ValueType expected)->Result<ExpressionPtr>{if(stack.empty())return unsupported("operand stack underflow");auto v=stack.back();stack.pop_back();if(expected.kind!=TypeKind::unknown&&v->type!=expected)return unsupported("operand stack type mismatch");return v;};
        auto emit=[&](std::size_t n,Statement statement){const auto *fact=code[n];lifted.instructions.push_back({{fact->instruction.address,fact->id},std::move(statement)});};
        const auto take_results = [&](const std::vector<ValueType> &types) -> Result<std::vector<ExpressionPtr>> {
            std::vector<ExpressionPtr> values(types.size());
            for (std::size_t i = types.size(); i > 0; --i) {
                auto value = pop(types[i - 1]);
                if (!value) return value.error();
                values[i - 1] = value.value();
            }
            return values;
        };
        const auto emit_return = [&](std::size_t n, const std::vector<ValueType> &types) -> Result<bool> {
            auto values = take_results(types);
            if (!values) return values.error();
            if (values.value().size() > 1) {
                emit(n, Intrinsic{"wasm_return_values", std::move(values.value()), IntrinsicMemoryEffect::none});
                emit(n, Return{});
            } else {
                emit(n, Return{values.value().empty() ? ExpressionPtr{} : values.value().front()});
            }
            return true;
        };
        const auto append_call_results = [&](Intrinsic &call,
                                             const std::vector<std::uint8_t> &type_codes) -> Result<bool> {
            if (type_codes.size() > max_stack - stack.size())
                return Error{ErrorCode::resource_limit, "WebAssembly call results exceed the 128-value operand-stack bound"};
            for (const auto code : type_codes) {
                const auto type = wasm_value_type(code);
                if (!type) return unsupported("call result type is unsupported");
                const auto slot = stack.size();
                const RegisterOperand reg{RegisterBank::wasm_stack, static_cast<std::uint8_t>(slot), type->bits, false};
                call.register_writes.push_back(reg);
                if (type_codes.size() == 1) call.result_type = *type;
                stack.push_back(std::make_shared<Expression>(Expression{*type, RegisterValue{reg, 0}}));
            }
            return true;
        };
        if (bi == 0 && !local_types.empty()) {
            const auto parameter_count = function_signature ? function_signature->parameter_types.size() : 0;
            const auto *origin = code[begin];
            for (std::size_t index = 0; index < local_types.size(); ++index) {
                ExpressionPtr initial;
                if (index < parameter_count)
                    initial = std::make_shared<Expression>(Expression{local_types[index], VariableValue{local_name(index)}});
                else
                    initial = constant(0, local_types[index]);
                lifted.instructions.push_back({{origin->instruction.address, origin->id},
                    Assign{local_register(index), std::move(initial)}});
            }
        }
        for(std::size_t n=begin;n<finish;++n){const auto *fact=code[n];const auto &i=fact->instruction;const auto op=std::to_integer<std::uint8_t>(i.bytes[0]);
            if(op==0xd0){stack.push_back(constant(0,funcref()));continue;}
            if(op==0xd2){auto index=immediate(i);if(!index)return unsupported("ref.func index unavailable");stack.push_back(unary("wasm_ref_func_"+std::to_string(*index),constant(0,funcref()),funcref()));continue;}
            if(op==0xd1){
                auto value=pop(funcref());if(!value)return value.error();
                // Preserve the exact result when the reference's nullness is
                // known locally. This also lets a following br_if use the
                // actual Wasm predicate rather than an opaque helper call.
                if (ref_is_null_input[n] == ReferenceNullness::null_value) {
                    stack.push_back(constant(1, integer(32)));
                } else if (ref_is_null_input[n] == ReferenceNullness::non_null) {
                    stack.push_back(constant(0, integer(32)));
                } else {
                    const auto inferred = expression_nullness(value.value());
                    if (inferred == ReferenceNullness::null_value)
                        stack.push_back(constant(1, integer(32)));
                    else if (inferred == ReferenceNullness::non_null)
                        stack.push_back(constant(0, integer(32)));
                    else
                        stack.push_back(unary("wasm_ref_is_null",value.value(),integer(32)));
                }
                continue;
            }
            if(op==0x41||op==0x42||op==0x43||op==0x44){auto v=immediate(i);if(!v)return unsupported("constant immediate unavailable");stack.push_back(constant(*v,op==0x41?integer(32):op==0x42?integer(64):op==0x43?floating(32):floating(64)));continue;}
            if(op==0x00){emit(n,Intrinsic{"wasm_unreachable",{},IntrinsicMemoryEffect::none});break;}
            if(op==0x01)continue;
            if(op==2||op==3){continue;}
            if(op==4){auto cond=pop(integer(32));if(!cond)return cond.error();const auto li=*opener_label[n];const auto yes_target=n+1;const auto no_target=labels[li].else_index<code.size()?labels[li].else_index+1:labels[li].end+1;const auto yes_block=block_for(yes_target),no_block=block_for(no_target);if(!yes_block||!no_block)return unsupported("if target is not a basic block");emit(n,Branch{"wasm_if",route_address(bi,*yes_block,{},BlockEdgeKind::conditional_true),route_address(bi,*no_block,{},BlockEdgeKind::conditional_false),cond.value()});continue;}
            if(op==5){const auto li=active_labels[n].back();auto values=take_results(labels[li].result_types);if(!values)return values.error();if(!label_heights[li]||stack.size()<*label_heights[li])return unsupported("if then-arm stack height is unavailable");stack.resize(*label_heights[li]);stack.insert(stack.end(),values.value().begin(),values.value().end());const auto target=labels[li].end+1;const auto target_block=block_for(target);if(!target_block)return unsupported("else target is not a basic block");emit(n,Branch{"true",route_address(bi,*target_block,li,BlockEdgeKind::jump),{}});continue;}
            if(op==0x0b){if(end_label[n]){const auto li=*end_label[n];auto values=take_results(labels[li].result_types);if(!values)return values.error();if(!label_heights[li]||stack.size()<*label_heights[li])return unsupported("block stack height is unavailable");stack.resize(*label_heights[li]);stack.insert(stack.end(),values.value().begin(),values.value().end());}else if(n==function_end){auto result=emit_return(n,function_result_types.value());if(!result)return result.error();}continue;}
            if(op==0x0f){auto result=emit_return(n,function_result_types.value());if(!result)return result.error();continue;}
            if(op==0x0c||op==0x0d){auto depth=immediate(i);if(!depth)return unsupported("branch depth unavailable");const auto li=active_labels[n][active_labels[n].size()-1-static_cast<std::size_t>(*depth)];const auto target=li==function_label?function_end:labels[li].kind==3?labels[li].opener+1:labels[li].end+1;const auto target_block=block_for(target);if(!target_block)return unsupported("branch target is not a basic block");const auto branch_kind=op==0x0c?BlockEdgeKind::jump:BlockEdgeKind::conditional_true;const auto branch_target=route_address(bi,*target_block,li,branch_kind);if(op==0x0c)emit(n,Branch{"true",branch_target,{}});else{auto cond=pop(integer(32));if(!cond)return cond.error();const auto fallthrough=n+1<code.size()?block_for(n+1):std::nullopt;emit(n,Branch{"br_if",branch_target,fallthrough?std::optional<Address>{route_address(bi,*fallthrough,{},BlockEdgeKind::conditional_false)}:std::nullopt,cond.value()});}continue;}
            if(op==0x0e){auto selector=pop(integer(32));if(!selector)return selector.error();auto targets=table_targets(n);if(!targets)return targets.error();LiftedBlock::SwitchDispatch dispatch;dispatch.selector=selector.value();for(const auto &target:targets.value()){const auto target_block=block_for(target.target);if(!target_block)return unsupported("br_table target is not a basic block");const auto address=route_address(bi,*target_block,target.label,BlockEdgeKind::jump);if(target.value)dispatch.cases.push_back({*target.value,address});else dispatch.default_target=address;}lifted.switch_dispatch=std::move(dispatch);continue;}
            if(op==0x1a){auto v=pop({});if(!v)return v.error();continue;}
            if(op==0x1b){auto cond=pop(integer(32));if(!cond)return cond.error();auto when_true=pop({});if(!when_true)return when_true.error();auto when_false=pop(when_true.value()->type);if(!when_false)return when_false.error();auto alternatives=binary("pair",when_true.value(),when_false.value(),when_true.value()->type);stack.push_back(binary("select_if",cond.value(),alternatives,when_true.value()->type));continue;}
            if(op==0x1c){const auto type_code=immediate(i);if(!type_code||*type_code>UINT8_MAX)return unsupported("typed select result type unavailable");const auto type=wasm_value_type(static_cast<std::uint8_t>(*type_code));if(!type)return unsupported("typed select result type is unsupported");auto cond=pop(integer(32));if(!cond)return cond.error();auto when_true=pop(*type);if(!when_true)return when_true.error();auto when_false=pop(*type);if(!when_false)return when_false.error();auto alternatives=binary("pair",when_true.value(),when_false.value(),*type);stack.push_back(binary("select_if",cond.value(),alternatives,*type));continue;}
            if (op >= 0x20 && op <= 0x22) {
                const auto index = immediate(code[n]->instruction);
                const auto type = index ? local_type(*index) : std::optional<ValueType>{};
                if (!index || !type)
                    return unsupported("local index is outside the typed parameter/local declarations");
                if (op == 0x20) {
                    const auto reg = local_register(*index);
                    stack.push_back(std::make_shared<Expression>(Expression{*type, RegisterValue{reg, 0}}));
                } else {
                    auto value = pop(*type);
                    if (!value) return value.error();
                    emit(n, Assign{local_register(*index), value.value()});
                    if (op == 0x22) stack.push_back(value.value());
                }
                if (stack.size() > max_stack)
                    return Error{ErrorCode::resource_limit, "WebAssembly operand stack exceeds 128 values"};
                continue;
            }
            if (op == 0x23 || op == 0x24) {
                const auto index = immediate(code[n]->instruction);
                if (!metadata || metadata->globals.size() !=
                        static_cast<std::uint64_t>(metadata->imported_globals) + metadata->defined_globals ||
                    !index || *index >= metadata->globals.size()) return unsupported("global index metadata unavailable");
                const auto &global = metadata->globals[static_cast<std::size_t>(*index)];
                const auto type = wasm_value_type(global.value_type);
                if (!type || (op == 0x24 && !global.mutable_value)) return unsupported("unsupported global type or immutable global.set");
                if (op == 0x23) {
                    Intrinsic get; get.name = "wasm_global_get_" + std::to_string(*index); get.memory_effect = IntrinsicMemoryEffect::unknown;
                    const auto slot = stack.size(); const RegisterOperand reg{RegisterBank::wasm_stack, static_cast<std::uint8_t>(slot), type->bits, false};
                    get.result_type = *type; get.register_writes.push_back(reg); emit(n, std::move(get));
                    stack.push_back(std::make_shared<Expression>(Expression{*type, RegisterValue{reg, 0}}));
                } else {
                    auto value = pop(*type); if (!value) return value.error();
                    Intrinsic set; set.name = "wasm_global_set_" + std::to_string(*index); set.operands.push_back(value.value());
                    set.memory_effect = IntrinsicMemoryEffect::unknown; emit(n, std::move(set));
                }
                continue;
            }
            if (op == 0x10) {
                const auto index = immediate(code[n]->instruction);
                const auto *callee = index ? signature_for(*index) : nullptr;
                if (!index || !callee || callee->parameter_count != callee->parameter_types.size() ||
                    callee->result_count != callee->result_types.size())
                    return unsupported("direct call target or function signature metadata is unavailable");
                if (callee->parameter_types.size() > max_stack || callee->result_types.size() > max_stack)
                    return Error{ErrorCode::resource_limit, "direct call exceeds the 128-value parameter/result bound"};
                std::vector<ExpressionPtr> arguments(callee->parameter_types.size());
                for (std::size_t argument = callee->parameter_types.size(); argument > 0; --argument) {
                    const auto type = wasm_value_type(callee->parameter_types[argument - 1]);
                    if (!type) return unsupported("direct call parameter type is unsupported");
                    auto value = pop(*type);
                    if (!value) return value.error();
                    arguments[argument - 1] = value.value();
                }
                Intrinsic call;
                call.name = "wasm_call_function_" + std::to_string(*index);
                call.operands = std::move(arguments);
                call.memory_effect = IntrinsicMemoryEffect::unknown;
                auto result_values = append_call_results(call, callee->result_types);
                if (!result_values) return result_values.error();
                emit(n, std::move(call));
                if (stack.size() > max_stack)
                    return Error{ErrorCode::resource_limit, "WebAssembly operand stack exceeds 128 values"};
                continue;
            }
            if (op == 0x11) {
                const auto type_index = immediate(i, 0), table_index = immediate(i, 1);
                if (!metadata || !type_index || !table_index || *table_index != 0 ||
                    static_cast<std::uint64_t>(metadata->imported_tables) + metadata->defined_tables != 1 ||
                    *type_index >= metadata->function_types.size())
                    return unsupported("call_indirect requires exact type and single-table metadata");
                const auto *callee = &metadata->function_types[static_cast<std::size_t>(*type_index)];
                if (callee->parameter_count != callee->parameter_types.size() ||
                    callee->result_count != callee->result_types.size() ||
                    callee->parameter_types.size() > 127 || callee->result_types.size() > max_stack)
                    return Error{ErrorCode::resource_limit, "call_indirect exceeds the 127-parameter or 128-result bound"};
                if (stack.empty() || stack.back()->type != integer(32))
                    return unsupported("call_indirect table index is unavailable or not i32");
                auto table_index_value = stack.back();
                stack.pop_back();
                lifted.trap_edges.push_back({i.address, TrapEdgeKind::may_trap,
                    "call_indirect table bounds or type mismatch",
                    unary("wasm_call_indirect_traps_type_" + std::to_string(*type_index),
                          table_index_value, integer(32))});
                const auto target_function = resolved_indirect_target(metadata,
                    static_cast<std::uint32_t>(*type_index), table_index_value);
                std::vector<ExpressionPtr> arguments(callee->parameter_types.size());
                for (std::size_t argument = callee->parameter_types.size(); argument > 0; --argument) {
                    const auto arg_type = wasm_value_type(callee->parameter_types[argument - 1]);
                    if (!arg_type) return unsupported("call_indirect parameter type is unsupported");
                    auto value = pop(*arg_type);
                    if (!value) return value.error();
                    arguments[argument - 1] = value.value();
                }
                Intrinsic call;
                call.name = "wasm_call_indirect_type_" + std::to_string(*type_index);
                if (target_function)
                    call.name += "_target_" + std::to_string(*target_function);
                call.operands = std::move(arguments);
                call.operands.push_back(std::move(table_index_value));
                call.memory_effect = IntrinsicMemoryEffect::unknown;
                auto result_values = append_call_results(call, callee->result_types);
                if (!result_values) return result_values.error();
                emit(n, std::move(call));
                continue;
            }
            if (op >= 0x28 && op <= 0x3e) {
                const auto info = memory_op(op);
                if (!info) return unsupported("memory opcode metadata is unavailable");
                auto args = memory_immediates(i, *info, metadata);
                if (!args) return args.error();

                ExpressionPtr stored;
                if (info->store) {
                    auto value = pop(info->stack_type);
                    if (!value) return value.error();
                    stored = value.value();
                }
                auto address = pop(integer(32));
                if (!address) return address.error();
                const auto effective_address = args.value().second
                    ? binary("add", address.value(), constant(args.value().second, integer(32)), integer(32))
                    : address.value();

                // Wasm traps when the complete access extends beyond the
                // current memory. Memory size is runtime state, so retain the
                // exact access width in a named predicate instead of
                // pretending the bounds check can be evaluated statically.
                const auto access_bytes = info->access_type.bits / 8;
                lifted.trap_edges.push_back({i.address, TrapEdgeKind::may_trap,
                    "WebAssembly memory access out of bounds",
                    wasm_memory_access_trap_condition(address.value(),
                        static_cast<std::uint32_t>(args.value().second), access_bytes)});

                // The common MemoryValue requires a register base. A reserved
                // Wasm stack pseudo-register carries the exact effective i32
                // address, preserving its wrapping addition and SSA inputs.
                const RegisterOperand address_register{RegisterBank::wasm_stack, 255, 32, false};
                emit(n, Assign{address_register, effective_address});
                MemoryValue memory;
                memory.type = info->access_type;
                memory.base = address_register;
                auto location = std::make_shared<Expression>(Expression{info->access_type, std::move(memory)});

                if (info->store) {
                    if (info->access_type.bits < info->stack_type.bits) {
                        const auto operation = "trunc" + std::to_string(info->access_type.bits);
                        stored = unary(operation, std::move(stored), info->access_type);
                    }
                    emit(n, Store{std::move(location), std::move(stored)});
                } else {
                    ExpressionPtr loaded = std::move(location);
                    if (info->access_type.bits < info->stack_type.bits) {
                        const auto operation = info->access_type.is_signed ? "sext" : "zext";
                        loaded = unary(std::string(operation) + std::to_string(info->access_type.bits),
                                       std::move(loaded), info->stack_type);
                    }
                    stack.push_back(std::move(loaded));
                }
                continue;
            }
            if (op == 0xfd) {
                const auto subopcode = simd_subopcode(i);
                const auto relaxed = subopcode ? simd_relaxed_op(*subopcode) : std::optional<SimdRelaxedOpInfo>{};
                if (relaxed) {
                    if (!i.operands.empty() || i.mnemonic_override != relaxed->name)
                        return unsupported("relaxed SIMD opcode metadata is inconsistent");
                    std::vector<ExpressionPtr> arguments(relaxed->input_count);
                    for (std::size_t operand = arguments.size(); operand > 0; --operand) {
                        auto value = pop(vector(128));
                        if (!value) return value.error();
                        arguments[operand - 1] = value.value();
                    }
                    if (stack.size() >= max_stack)
                        return Error{ErrorCode::resource_limit, "WebAssembly operand stack exceeds 128 values"};
                    const auto slot = stack.size();
                    const RegisterOperand result_register{RegisterBank::wasm_stack,
                        static_cast<std::uint8_t>(slot), 128, false};
                    Intrinsic operation{simd_relaxed_intrinsic_name(relaxed->name), std::move(arguments),
                                        IntrinsicMemoryEffect::none};
                    operation.register_writes.push_back(result_register);
                    stack.push_back(std::make_shared<Expression>(Expression{
                        vector(128), RegisterValue{result_register, 0}}));
                    emit(n, std::move(operation));
                    continue;
                }
                const auto integer_unary = subopcode ? simd_integer_unary(*subopcode) : std::optional<SimdIntegerUnaryInfo>{};
                if (integer_unary) {
                    auto value = pop(vector(128));
                    if (!value) return value.error();
                    stack.push_back(unary(std::string(integer_unary->name), value.value(), integer_unary->result_type));
                    continue;
                }
                if (subopcode && *subopcode == 13) {
                    // The shuffle selector is an instruction immediate, not a
                    // runtime vector. Keep its complete validated byte-lane
                    // map in the operation name so the typed binary IR stays
                    // deterministic without inventing a third expression
                    // operand or dropping lane provenance.
                    if (i.operands.size() != 16)
                        return unsupported("SIMD shuffle requires exactly sixteen lane selectors");
                    std::string operation = "wasm_i8x16_shuffle_";
                    for (std::size_t lane = 0; lane < i.operands.size(); ++lane) {
                        const auto selected = immediate(i, lane);
                        if (!selected || *selected >= 32)
                            return unsupported("SIMD shuffle selector is missing or outside the two input vectors");
                        if (lane) operation.push_back('_');
                        operation += std::to_string(*selected);
                    }
                    auto second = pop(vector(128));
                    auto first = pop(vector(128));
                    if (!second) return second.error();
                    if (!first) return first.error();
                    stack.push_back(binary(std::move(operation), first.value(), second.value(), vector(128)));
                    continue;
                }
                if (subopcode && *subopcode == 14) {
                    auto indices = pop(vector(128));
                    auto source = pop(vector(128));
                    if (!indices) return indices.error();
                    if (!source) return source.error();
                    stack.push_back(binary("wasm_i8x16_swizzle", source.value(), indices.value(), vector(128)));
                    continue;
                }
                const auto float_unary = subopcode ? simd_float_unary(*subopcode) : std::optional<std::string_view>{};
                if (float_unary) {
                    if (!i.operands.empty() || i.mnemonic_override != *float_unary)
                        return unsupported("SIMD floating unary opcode metadata is inconsistent");
                    auto value = pop(vector(128));
                    if (!value) return value.error();
                    stack.push_back(unary(std::string(*float_unary), value.value(), vector(128)));
                    continue;
                }
                const auto float_binary = subopcode ? simd_float_binary(*subopcode) : std::optional<std::string_view>{};
                if (float_binary) {
                    if (!i.operands.empty() || i.mnemonic_override != *float_binary)
                        return unsupported("SIMD floating binary opcode metadata is inconsistent");
                    auto right = pop(vector(128));
                    auto left = pop(vector(128));
                    if (!right) return right.error();
                    if (!left) return left.error();
                    stack.push_back(binary(std::string(*float_binary), left.value(), right.value(), vector(128)));
                    continue;
                }
                const auto conversion = subopcode ? simd_conversion(*subopcode) : std::optional<std::string_view>{};
                if (conversion) {
                    if (!i.operands.empty() || i.mnemonic_override != *conversion)
                        return unsupported("SIMD conversion opcode metadata is inconsistent");
                    auto value = pop(vector(128));
                    if (!value) return value.error();
                    stack.push_back(unary(std::string(*conversion), value.value(), vector(128)));
                    continue;
                }
                const auto splat = subopcode ? simd_splat_op(*subopcode) : std::optional<SimdSplatOpInfo>{};
                if (splat) {
                    auto scalar = pop(splat->scalar_type);
                    if (!scalar) return scalar.error();
                    stack.push_back(unary(std::string(splat->name), scalar.value(), vector(128)));
                    continue;
                }
                const auto lane = subopcode ? simd_lane_op(*subopcode) : std::optional<SimdLaneOpInfo>{};
                if (lane) {
                    const auto lane_index = immediate(i, 0);
                    if (!lane_index || *lane_index >= lane->lane_count)
                        return unsupported("SIMD lane immediate is missing or outside its lane count");
                    const auto vector_type = vector(128);
                    const auto lane_name = std::string(lane->name) + "_" + std::to_string(*lane_index);
                    if (lane->replace) {
                        auto scalar = pop(lane->scalar_type);
                        auto value = pop(vector_type);
                        if (!scalar) return scalar.error();
                        if (!value) return value.error();
                        Intrinsic replace{lane_name, {value.value(), scalar.value()}, IntrinsicMemoryEffect::none};
                        if (stack.size() >= max_stack)
                            return Error{ErrorCode::resource_limit, "WebAssembly operand stack exceeds 128 values"};
                        const auto slot = stack.size();
                        const RegisterOperand result_register{RegisterBank::wasm_stack,
                            static_cast<std::uint8_t>(slot), vector_type.bits, false};
                        replace.register_writes.push_back(result_register);
                        stack.push_back(std::make_shared<Expression>(Expression{
                            vector_type, RegisterValue{result_register, 0}}));
                        emit(n, std::move(replace));
                    } else {
                        auto value = pop(vector_type);
                        if (!value) return value.error();
                        stack.push_back(unary(lane_name, value.value(), lane->scalar_type));
                    }
                    continue;
                }
                if (subopcode && (*subopcode == 77 || (*subopcode >= 78 && *subopcode <= 83))) {
                    const auto vector_type = vector(128);
                    if (*subopcode == 77) {
                        auto value = pop(vector_type);
                        if (!value) return value.error();
                        stack.push_back(unary("not", value.value(), vector_type));
                    } else if (*subopcode >= 78 && *subopcode <= 81) {
                        auto right = pop(vector_type);
                        auto left = pop(vector_type);
                        if (!right) return right.error();
                        if (!left) return left.error();
                        ExpressionPtr value;
                        if (*subopcode == 78) value = binary("and", left.value(), right.value(), vector_type);
                        else if (*subopcode == 79)
                            value = binary("and", left.value(), unary("not", right.value(), vector_type), vector_type);
                        else if (*subopcode == 80) value = binary("or", left.value(), right.value(), vector_type);
                        else value = binary("xor", left.value(), right.value(), vector_type);
                        stack.push_back(std::move(value));
                    } else if (*subopcode == 82) {
                        auto mask = pop(vector_type);
                        auto second = pop(vector_type);
                        auto first = pop(vector_type);
                        if (!mask) return mask.error();
                        if (!second) return second.error();
                        if (!first) return first.error();
                        auto selected_first = binary("and", first.value(), mask.value(), vector_type);
                        auto selected_second = binary("and", second.value(),
                            unary("not", mask.value(), vector_type), vector_type);
                        stack.push_back(binary("or", std::move(selected_first),
                            std::move(selected_second), vector_type));
                    } else {
                        auto value = pop(vector_type);
                        if (!value) return value.error();
                        stack.push_back(unary("wasm_v128_any_true", value.value(), integer(32)));
                    }
                    continue;
                }
                if (subopcode && ((*subopcode >= 0x23 && *subopcode <= 0x4c) ||
                                  (*subopcode >= 0xd6 && *subopcode <= 0xdb))) {
                    // SIMD comparison results are lane masks represented as
                    // opaque v128 values. Keep the exact decoded mnemonic so
                    // signedness and lane width survive lifting.
                    if (i.mnemonic_override.empty())
                        return unsupported("SIMD comparison mnemonic is unavailable");
                    auto right = pop(vector(128));
                    auto left = pop(vector(128));
                    if (!right) return right.error();
                    if (!left) return left.error();
                    stack.push_back(binary(i.mnemonic_override, left.value(), right.value(), vector(128)));
                    continue;
                }
                if (subopcode) {
                    if (const auto operation = simd_integer_extmul(*subopcode)) {
                        if (!i.operands.empty() || i.mnemonic_override != *operation)
                            return unsupported("SIMD extended-multiply opcode metadata is inconsistent");
                        auto right = pop(vector(128));
                        auto left = pop(vector(128));
                        if (!right) return right.error();
                        if (!left) return left.error();
                        stack.push_back(binary(std::string(*operation), left.value(), right.value(), vector(128)));
                        continue;
                    }
                    if (const auto operation = wasm_simd_integer_binary_op(*subopcode)) {
                        auto right = pop(vector(128));
                        auto left = pop(vector(128));
                        if (!right) return right.error();
                        if (!left) return left.error();
                        // Generic 128-bit arithmetic would introduce cross-lane carries.
                        stack.push_back(binary(std::string(operation->name), left.value(), right.value(), vector(128)));
                        continue;
                    }
                    if (const auto operation = simd_integer_shift(*subopcode)) {
                        auto shift = pop(integer(32));
                        auto value = pop(vector(128));
                        if (!shift) return shift.error();
                        if (!value) return value.error();
                        stack.push_back(binary(std::string(*operation), value.value(), shift.value(), vector(128)));
                        continue;
                    }
                    if (simd_integer_extend_or_pairwise_add(*subopcode)) {
                        if (i.mnemonic_override.empty())
                            return unsupported("SIMD extension mnemonic is unavailable");
                        auto value = pop(vector(128));
                        if (!value) return value.error();
                        stack.push_back(unary(i.mnemonic_override, value.value(), vector(128)));
                        continue;
                    }
                    if (simd_integer_narrow(*subopcode)) {
                        if (i.mnemonic_override.empty())
                            return unsupported("SIMD narrowing mnemonic is unavailable");
                        auto high = pop(vector(128));
                        auto low = pop(vector(128));
                        if (!high) return high.error();
                        if (!low) return low.error();
                        stack.push_back(binary(i.mnemonic_override, low.value(), high.value(), vector(128)));
                        continue;
                    }
                }
                const auto info = subopcode ? simd_memory_op(*subopcode) : std::optional<SimdMemoryOpInfo>{};
                if (!info) return unsupported("SIMD instruction is outside the supported memory subset");
                if (!metadata || static_cast<std::uint64_t>(metadata->imported_memories) + metadata->defined_memories != 1)
                    return unsupported("SIMD memory operation requires exactly one validated module memory");
                const auto alignment = immediate(i, 0);
                const auto offset = immediate(i, 1);
                const auto expected_operands = info->lane_indexed ? 3u : 2u;
                if (i.operands.size() != expected_operands || !alignment || !offset ||
                    *alignment > info->maximum_alignment_exponent || *offset > UINT32_MAX)
                    return unsupported("SIMD memory alignment or offset immediate is malformed or out of bounds");
                if (info->lane_indexed) {
                    const auto lane = immediate(i, 2);
                    const auto lane_count = 128u / info->access_bits;
                    if (i.operands.size() != 3 || !lane || *lane >= lane_count)
                        return unsupported("SIMD lane memory operation has a missing or out-of-range lane index");
                    auto value = pop(vector(128));
                    auto address = pop(integer(32));
                    if (!value) return value.error();
                    if (!address) return address.error();
                    const auto effective_address = *offset
                        ? binary("add", address.value(), constant(*offset, integer(32)), integer(32))
                        : address.value();
                    const auto access_bytes = info->access_bits / 8;
                    lifted.trap_edges.push_back({i.address, TrapEdgeKind::may_trap,
                        "WebAssembly SIMD lane memory access out of bounds",
                        wasm_memory_access_trap_condition(address.value(),
                            static_cast<std::uint32_t>(*offset), access_bytes)});
                    const RegisterOperand address_register{RegisterBank::wasm_stack, 255, 32, false};
                    emit(n, Assign{address_register, effective_address});
                    MemoryValue memory;
                    memory.type = info->memory_type;
                    memory.base = address_register;
                    auto location = std::make_shared<Expression>(Expression{info->memory_type, std::move(memory)});
                    const auto lane_name = std::to_string(info->access_bits) + "_" + std::to_string(*lane);
                    if (info->store) {
                        auto stored = unary("wasm_v128_extract_lane_" + lane_name,
                                            value.value(), info->memory_type);
                        emit(n, Store{std::move(location), std::move(stored)});
                    } else {
                        Intrinsic load{"wasm_v128_load_lane_" + lane_name,
                            {value.value(), std::move(location)}, IntrinsicMemoryEffect::read};
                        if (stack.size() >= max_stack)
                            return Error{ErrorCode::resource_limit, "WebAssembly operand stack exceeds 128 values"};
                        const auto slot = stack.size();
                        const RegisterOperand result_register{RegisterBank::wasm_stack,
                            static_cast<std::uint8_t>(slot), 128, false};
                        load.register_writes.push_back(result_register);
                        stack.push_back(std::make_shared<Expression>(Expression{
                            vector(128), RegisterValue{result_register, 0}}));
                        emit(n, std::move(load));
                    }
                    continue;
                }
                ExpressionPtr stored;
                if (info->store) {
                    auto value = pop(info->stack_type);
                    if (!value) return value.error();
                    stored = value.value();
                }
                auto address = pop(integer(32));
                if (!address) return address.error();
                const auto effective_address = *offset
                    ? binary("add", address.value(), constant(*offset, integer(32)), integer(32))
                    : address.value();
                const auto access_bytes = info->access_bits / 8;
                lifted.trap_edges.push_back({i.address, TrapEdgeKind::may_trap,
                    "WebAssembly SIMD memory access out of bounds",
                    wasm_memory_access_trap_condition(address.value(),
                        static_cast<std::uint32_t>(*offset), access_bytes)});
                const RegisterOperand address_register{RegisterBank::wasm_stack, 255, 32, false};
                emit(n, Assign{address_register, effective_address});
                MemoryValue memory;
                memory.type = info->memory_type;
                memory.base = address_register;
                auto location = std::make_shared<Expression>(Expression{info->memory_type, std::move(memory)});
                if (info->store) {
                    emit(n, Store{std::move(location), std::move(stored)});
                } else if (info->load_operation.empty()) {
                    stack.push_back(std::move(location));
                } else {
                    stack.push_back(unary(std::string(info->load_operation), std::move(location), info->stack_type));
                }
                continue;
            }
            if (op == 0x3f || op == 0x40) {
                const auto memory_index = immediate(code[n]->instruction);
                if (!metadata ||
                    static_cast<std::uint64_t>(metadata->imported_memories) + metadata->defined_memories != 1 ||
                    !memory_index || *memory_index != 0)
                    return unsupported("memory.size/grow requires one validated memory at index zero");

                Intrinsic effect;
                if (op == 0x3f) {
                    effect.name = "wasm_memory_size_pages";
                } else {
                    auto delta = pop(integer(32));
                    if (!delta) return delta.error();
                    effect.name = "wasm_memory_grow_pages";
                    effect.operands.push_back(delta.value());
                }
                // The current page count is runtime state. Growth changes the
                // addressable memory; a failed grow is represented by the
                // intrinsic's i32 -1 result rather than a trap edge.
                effect.memory_effect = op == 0x3f ? IntrinsicMemoryEffect::read
                                                  : IntrinsicMemoryEffect::unknown;
                const std::vector<std::uint8_t> result_types{0x7f};
                auto result_values = append_call_results(effect, result_types);
                if (!result_values) return result_values.error();
                emit(n, std::move(effect));
                continue;
            }
            if (op == 0xfc) {
                const auto subopcode = bulk_memory_subopcode(i);
                if (!subopcode || !valid_bulk_memory_indices(i, metadata, *subopcode))
                    return unsupported("bulk-memory instruction requires validated segment and single-memory indices");
                if (*subopcode <= 7) {
                    const auto cv = saturating_conversion(*subopcode);
                    if (!cv) return unsupported("trunc_sat subopcode is unavailable");
                    auto operand = pop(cv->input);
                    if (!operand) return operand.error();
                    stack.push_back(unary(std::string(cv->operation), operand.value(), cv->output));
                    continue;
                }
                Intrinsic effect;
                if (*subopcode == 9) {
                    effect.name = "wasm_data_drop_segment_" + std::to_string(*immediate(i, 0));
                    effect.memory_effect = IntrinsicMemoryEffect::none;
                } else if (*subopcode == 13) {
                    effect.name = "wasm_element_drop_segment_" + std::to_string(*immediate(i, 0));
                    effect.memory_effect = IntrinsicMemoryEffect::unknown;
                } else if (*subopcode >= 12) {
                    const auto table_range_oob = [&](const ExpressionPtr &address,
                                                     const ExpressionPtr &length) {
                        return binary("wasm_table_range_out_of_bounds_table_0", address, length, integer(32));
                    };
                    if (*subopcode == 12) {
                        const auto element_index = *immediate(i, 0);
                        auto length = pop(integer(32));
                        auto source = pop(integer(32));
                        auto destination = pop(integer(32));
                        if (!length) return length.error();
                        if (!source) return source.error();
                        if (!destination) return destination.error();
                        effect.name = "wasm_table_init_element_" + std::to_string(element_index);
                        effect.operands = {destination.value(), source.value(), length.value()};
                        effect.memory_effect = IntrinsicMemoryEffect::unknown;
                        const auto &segment = metadata->element_segments[static_cast<std::size_t>(element_index)];
                        const auto source_oob = binary(
                            "wasm_element_segment_" + std::to_string(element_index) +
                                "_source_range_out_of_bounds_count_" +
                                std::to_string(segment.function_indices.size()),
                            source.value(), length.value(), integer(32));
                        const auto dropped = unary("wasm_element_segment_" + std::to_string(element_index) +
                                                       "_dropped_and_length_nonzero",
                                                   length.value(), integer(32));
                        const auto condition = binary("or", table_range_oob(destination.value(), length.value()),
                            binary("or", source_oob, dropped, integer(32)), integer(32));
                        lifted.trap_edges.push_back({i.address, TrapEdgeKind::may_trap,
                            effect.name + " bounds or dropped-segment trap", condition});
                    } else if (*subopcode == 14) {
                        auto length = pop(integer(32));
                        auto source = pop(integer(32));
                        auto destination = pop(integer(32));
                        if (!length) return length.error();
                        if (!source) return source.error();
                        if (!destination) return destination.error();
                        effect.name = "wasm_table_copy";
                        effect.operands = {destination.value(), source.value(), length.value()};
                        effect.memory_effect = IntrinsicMemoryEffect::unknown;
                        const auto condition = binary("or", table_range_oob(destination.value(), length.value()),
                            table_range_oob(source.value(), length.value()), integer(32));
                        lifted.trap_edges.push_back({i.address, TrapEdgeKind::may_trap,
                            "wasm_table_copy bounds trap", condition});
                    } else if (*subopcode == 15) {
                        auto delta = pop(integer(32));
                        auto value = pop(funcref());
                        if (!delta) return delta.error();
                        if (!value) return value.error();
                        effect.name = "wasm_table_grow_elements";
                        effect.operands = {value.value(), delta.value()};
                        effect.memory_effect = IntrinsicMemoryEffect::unknown;
                        auto results = append_call_results(effect, {0x7f});
                        if (!results) return results.error();
                    } else if (*subopcode == 16) {
                        effect.name = "wasm_table_size_elements";
                        effect.memory_effect = IntrinsicMemoryEffect::read;
                        auto results = append_call_results(effect, {0x7f});
                        if (!results) return results.error();
                    } else {
                        auto length = pop(integer(32));
                        auto value = pop(funcref());
                        auto destination = pop(integer(32));
                        if (!length) return length.error();
                        if (!value) return value.error();
                        if (!destination) return destination.error();
                        effect.name = "wasm_table_fill";
                        effect.operands = {destination.value(), value.value(), length.value()};
                        effect.memory_effect = IntrinsicMemoryEffect::unknown;
                        lifted.trap_edges.push_back({i.address, TrapEdgeKind::may_trap,
                            "wasm_table_fill bounds trap", table_range_oob(destination.value(), length.value())});
                    }
                } else {
                    const char *name = *subopcode == 8 ? "wasm_memory_init_data_" :
                                       *subopcode == 10 ? "wasm_memory_copy" : "wasm_memory_fill";
                    effect.name = name;
                    if (*subopcode == 8) effect.name += std::to_string(*immediate(i, 0));
                    // Stack order is destination, source/value, then length.
                    // Intrinsic operands retain the source-level order.
                    auto length = pop(integer(32));
                    auto source_or_value = pop(integer(32));
                    auto destination = pop(integer(32));
                    if (!length) return length.error();
                    if (!source_or_value) return source_or_value.error();
                    if (!destination) return destination.error();
                    effect.operands = {destination.value(), source_or_value.value(), length.value()};
                    effect.memory_effect = *subopcode == 11 ? IntrinsicMemoryEffect::write
                                                            : IntrinsicMemoryEffect::unknown;
                    const auto memory_range_oob = [&](const ExpressionPtr &address) {
                        return binary("wasm_memory_range_out_of_bounds", address, length.value(), integer(32));
                    };
                    ExpressionPtr trap_condition;
                    if (*subopcode == 8) {
                        const auto data_index = *immediate(i, 0);
                        const auto &segment = metadata->data_segments[static_cast<std::size_t>(data_index)];
                        const auto source_oob = binary(
                            "wasm_data_segment_" + std::to_string(data_index) +
                                "_source_range_out_of_bounds_size_" + std::to_string(segment.byte_count),
                            source_or_value.value(), length.value(), integer(32));
                        const auto segment_dropped = unary(
                            "wasm_data_segment_" + std::to_string(data_index) +
                                "_dropped_and_length_nonzero",
                            length.value(), integer(32));
                        trap_condition = binary("or", memory_range_oob(destination.value()),
                            binary("or", source_oob, segment_dropped, integer(32)), integer(32));
                    } else if (*subopcode == 10) {
                        trap_condition = binary("or", memory_range_oob(destination.value()),
                            memory_range_oob(source_or_value.value()), integer(32));
                    } else {
                        trap_condition = memory_range_oob(destination.value());
                    }
                    lifted.trap_edges.push_back({i.address, TrapEdgeKind::may_trap,
                        effect.name + (*subopcode == 8 ? " bounds or dropped-segment trap" : " out of bounds"),
                        std::move(trap_condition)});
                }
                emit(n, std::move(effect));
                continue;
            }
            if (auto info = numeric(op)) {
                if (info->pops == 1) {
                    auto operand = pop(info->input);
                    if (!operand) return operand.error();
                    stack.push_back(unary(std::string(info->op), operand.value(), info->output));
                } else {
                    auto right = pop(info->input);
                    if (!right) return right.error();
                    auto left = pop(info->input);
                    if (!left) return left.error();
                    if ((op >= 0x6d && op <= 0x70) || (op >= 0x7f && op <= 0x82)) {
                        const auto width = op <= 0x70 ? 32u : 64u;
                        lifted.trap_edges.push_back({i.address, TrapEdgeKind::may_trap,
                            std::string(info->op), integer_trap_condition(op, left.value(), right.value(), width)});
                    }
                    stack.push_back(binary(std::string(info->op), left.value(), right.value(), info->output));
                }
                continue;
            }
            if (auto cv = conversion(op)) {
                auto operand = pop(cv->input);
                if (!operand) return operand.error();
                if ((op >= 0xa8 && op <= 0xab) || (op >= 0xae && op <= 0xb1))
                    lifted.trap_edges.push_back({i.address, TrapEdgeKind::may_trap,
                        std::string(cv->operation), float_to_integer_trap_condition(op, operand.value())});
                stack.push_back(unary(std::string(cv->operation), operand.value(), cv->output));
                continue;
            }
            if (const auto ext = sign_extension(op)) {
                auto operand = pop(ext->type);
                if (!operand) return operand.error();
                stack.push_back(unary("sext" + std::to_string(ext->source_bits),
                                      operand.value(), ext->type));
                continue;
            }
            if(op>=0xa7&&op<=0xbf)return unsupported("numeric conversion or reinterpret opcode is not modeled");
            return unsupported("opcode/effect is not in the typed scalar subset: "+i.mnemonic_override);
        }
        if(!output_versions[bi].empty()){
            std::vector<LiftedInstruction> copies;copies.reserve(output_versions[bi].size());
            const auto *origin=code[last];
            for(std::size_t slot=0;slot<output_versions[bi].size();++slot){const RegisterOperand reg{RegisterBank::wasm_stack,static_cast<std::uint8_t>(slot),exits[bi]->at(slot).bits,false};copies.push_back({{origin->instruction.address,origin->id},Assign{reg,stack[slot],output_versions[bi][slot]}});}
            if(!lifted.instructions.empty()&&(std::holds_alternative<Branch>(lifted.instructions.back().statement)||std::holds_alternative<Return>(lifted.instructions.back().statement)))lifted.instructions.insert(lifted.instructions.end()-1,std::make_move_iterator(copies.begin()),std::make_move_iterator(copies.end()));else lifted.instructions.insert(lifted.instructions.end(),std::make_move_iterator(copies.begin()),std::make_move_iterator(copies.end()));
        }
        out.blocks.push_back(std::move(lifted));
    }
    for (const auto &bridge : edge_bridges) {
        const auto index = starts.size() + static_cast<std::size_t>(&bridge - edge_bridges.data());
        LiftedBlock lifted{bridge_id(index), bridge_address(index), {}, {}};
        lifted.successors.push_back({bridge_address(index),
            code[starts[bridge.target]]->instruction.address,
            BlockId{static_cast<std::uint64_t>(bridge.target + 1)}, BlockEdgeKind::jump});
        for (std::size_t slot = 0; slot < bridge.source_slots.size(); ++slot) {
            const auto source_slot = bridge.source_slots[slot];
            if (source_slot >= output_versions[bridge.source].size())
                return Error{ErrorCode::malformed, "WebAssembly edge bridge source value is unavailable"};
            const RegisterOperand reg{RegisterBank::wasm_stack, static_cast<std::uint8_t>(slot),
                entries[index]->at(slot).bits, false};
            auto value = std::make_shared<Expression>(Expression{
                exits[bridge.source]->at(source_slot),
                RegisterValue{RegisterOperand{RegisterBank::wasm_stack,
                    static_cast<std::uint8_t>(source_slot), exits[bridge.source]->at(source_slot).bits, false},
                    output_versions[bridge.source][source_slot]}});
            lifted.instructions.push_back({{bridge.source_address, 0},
                Assign{reg, std::move(value), output_versions[index][slot]}});
        }
        out.blocks.push_back(std::move(lifted));
    }
    return out;
}
} // namespace hexlab::decompiler
