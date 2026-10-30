#include "hexlab/decompiler/dex_lifting.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string_view>

namespace hexlab::decompiler {
namespace {
std::uint16_t unit(const Instruction &instruction, unsigned index) {
    const auto offset = index * 2;
    return std::uint16_t(std::to_integer<std::uint8_t>(instruction.bytes[offset])) |
        (std::uint16_t(std::to_integer<std::uint8_t>(instruction.bytes[offset + 1])) << 8);
}

RegisterOperand vreg(std::uint16_t index) {
    return {RegisterBank::dex_vreg, index, 32, false};
}

ValueType i32() { return {TypeKind::integer, 32, true}; }
ValueType i64() { return {TypeKind::integer, 64, true}; }
ValueType f32() { return {TypeKind::floating, 32, false}; }
ValueType f64() { return {TypeKind::floating, 64, false}; }
ValueType unknown_type(unsigned bits) { return {TypeKind::unknown, static_cast<std::uint16_t>(bits), false}; }
ValueType pointer32() { return {TypeKind::pointer, 32, false}; }
ValueType boolean_type() { return {TypeKind::boolean, 1, false}; }
std::string string_constant_preview(std::string_view value) {
    constexpr std::size_t limit = 96;
    constexpr char hex[] = "0123456789abcdef";
    std::string out;
    const auto count = std::min(value.size(), limit);
    out.reserve(count * 4 + 16);
    for (std::size_t i = 0; i < count; ++i) {
        const auto c = static_cast<unsigned char>(value[i]);
        if (c == '\\' || c == '"') { out.push_back('\\'); out.push_back(static_cast<char>(c)); }
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (c < 0x20 || c >= 0x7f) {
            out += "\\x"; out.push_back(hex[c >> 4]); out.push_back(hex[c & 0x0f]);
        } else out.push_back(static_cast<char>(c));
    }
    if (value.size() > count) out += "...";
    return out;
}
ExpressionPtr reg(RegisterOperand value) {
    return std::make_shared<Expression>(Expression{i32(), RegisterValue{value}});
}
ExpressionPtr typed_reg(RegisterOperand value, ValueType type) {
    return std::make_shared<Expression>(Expression{type, RegisterValue{value}});
}
ExpressionPtr wide_reg(RegisterOperand value) {
    return std::make_shared<Expression>(Expression{i64(), RegisterValue{value}});
}
ExpressionPtr unary(std::string operation, ExpressionPtr operand, ValueType type) {
    return std::make_shared<Expression>(Expression{type, UnaryValue{std::move(operation), std::move(operand)}});
}
ExpressionPtr constant(std::uint32_t value) {
    return std::make_shared<Expression>(Expression{i32(), ConstantValue{value, i32()}});
}
ExpressionPtr wide_constant(std::uint64_t value) {
    return std::make_shared<Expression>(Expression{i64(), ConstantValue{value, i64()}});
}
ExpressionPtr unknown_value(ValueType type, std::string description) {
    return std::make_shared<Expression>(Expression{type, UnknownValue{std::move(description)}});
}
ExpressionPtr binary(std::string op, ExpressionPtr left, ExpressionPtr right) {
    return std::make_shared<Expression>(Expression{i32(), BinaryValue{std::move(op), std::move(left), std::move(right)}});
}
ExpressionPtr wide_binary(std::string op, ExpressionPtr left, ExpressionPtr right) {
    return std::make_shared<Expression>(Expression{i64(), BinaryValue{std::move(op), std::move(left), std::move(right)}});
}
ExpressionPtr predicate(std::string op, ExpressionPtr left, ExpressionPtr right) {
    return std::make_shared<Expression>(Expression{{TypeKind::boolean, 1, false},
        BinaryValue{std::move(op), std::move(left), std::move(right)}});
}

struct DexCallResultShape {
    bool known = false;
    bool is_void = false;
    ValueType type;
};

struct DexParameterShape {
    ValueType type;
    std::uint8_t words = 1;
};

Result<ValueType> dex_type_value(const DexMetadata &metadata, std::uint32_t type_index) {
    if (type_index >= metadata.type_descriptors.size())
        return Error{ErrorCode::malformed, "DEX type index is outside retained descriptor metadata"};
    const auto &descriptor = metadata.type_descriptors[type_index];
    if (descriptor == "Z") return boolean_type();
    if (descriptor == "B") return ValueType{TypeKind::integer, 8, true};
    if (descriptor == "S") return ValueType{TypeKind::integer, 16, true};
    if (descriptor == "C") return ValueType{TypeKind::integer, 16, false};
    if (descriptor == "I") return i32();
    if (descriptor == "J") return i64();
    if (descriptor == "F") return f32();
    if (descriptor == "D") return f64();
    if (!descriptor.empty() && (descriptor.front() == 'L' || descriptor.front() == '[')) return pointer32();
    return Error{ErrorCode::malformed, "DEX prototype references a non-value type descriptor"};
}

enum class DexDescriptorConstraint { any, class_type, array_type };

Result<bool> validate_type_descriptor(const DexMetadata *metadata, std::uint32_t type_index,
                                     DexDescriptorConstraint constraint,
                                     std::string_view operation) {
    if (!metadata) return true;
    if (type_index >= metadata->type_descriptors.size())
        return Error{ErrorCode::malformed, "DEX " + std::string(operation) +
                     " type index is outside retained descriptor metadata"};
    const auto &descriptor = metadata->type_descriptors[type_index];
    const bool matches = !descriptor.empty() &&
        (constraint == DexDescriptorConstraint::any ||
         (constraint == DexDescriptorConstraint::class_type && descriptor.front() == 'L') ||
         (constraint == DexDescriptorConstraint::array_type && descriptor.front() == '['));
    if (!matches)
        return Error{ErrorCode::malformed, "DEX " + std::string(operation) +
                     " type descriptor has the wrong kind"};
    return true;
}

Result<std::optional<std::vector<DexParameterShape>>> call_parameter_shapes(
    const Instruction &instruction, const DexMetadata *metadata) {
    if (!metadata || metadata->prototype_parameter_word_counts.empty() ||
        metadata->prototype_parameter_offsets.empty() || metadata->type_descriptors.empty())
        return std::optional<std::vector<DexParameterShape>>{};
    const auto first = unit(instruction, 0);
    const auto op = static_cast<std::uint8_t>(first & 0xff);
    std::optional<std::uint32_t> proto_index;
    bool receiver = false;
    if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
        const auto method_index = unit(instruction, 1);
        if (method_index >= metadata->method_prototype_indices.size())
            return Error{ErrorCode::malformed, "DEX invoke method index is outside retained method metadata"};
        proto_index = metadata->method_prototype_indices[method_index];
        receiver = op != 0x71 && op != 0x77;
    } else if (op == 0xfa || op == 0xfb) {
        proto_index = unit(instruction, 3);
        receiver = true;
    } else if (op == 0xfc || op == 0xfd) {
        const auto call_site_index = unit(instruction, 1);
        if (call_site_index >= metadata->call_sites.size())
            return Error{ErrorCode::malformed, "DEX invoke-custom call-site index is outside retained metadata"};
        const auto &site = metadata->call_sites[call_site_index];
        if (site.values.size() < 3 || site.values[2].type != 0x15 || site.values[2].payload > UINT32_MAX)
            return std::optional<std::vector<DexParameterShape>>{};
        proto_index = static_cast<std::uint32_t>(site.values[2].payload);
    } else return std::optional<std::vector<DexParameterShape>>{};
    if (*proto_index >= metadata->prototype_parameter_word_counts.size() ||
        *proto_index + 1 >= metadata->prototype_parameter_offsets.size())
        return Error{ErrorCode::malformed, "DEX invoke prototype is outside retained parameter metadata"};
    const auto begin = metadata->prototype_parameter_offsets[*proto_index];
    const auto end = metadata->prototype_parameter_offsets[*proto_index + 1];
    if (begin > end || end > metadata->prototype_parameter_type_indices.size())
        return Error{ErrorCode::malformed, "DEX prototype parameter type range is invalid"};
    std::vector<DexParameterShape> shapes;
    shapes.reserve((end - begin) + (receiver ? 1u : 0u));
    std::uint32_t words = 0;
    if (receiver) {
        shapes.push_back({pointer32(), 1});
        ++words;
    }
    for (auto index = begin; index < end; ++index) {
        const auto type_index = metadata->prototype_parameter_type_indices[index];
        auto type = dex_type_value(*metadata, type_index);
        if (!type) return type.error();
        const auto &descriptor = metadata->type_descriptors[type_index];
        const auto width = static_cast<std::uint8_t>(descriptor == "J" || descriptor == "D" ? 2 : 1);
        words += width;
        shapes.push_back({type.value(), width});
    }
    const auto receiver_words = receiver ? 1u : 0u;
    if (words < receiver_words || words - receiver_words != metadata->prototype_parameter_word_counts[*proto_index])
        return Error{ErrorCode::malformed, "DEX prototype parameter word count disagrees with its type descriptors"};
    return std::optional<std::vector<DexParameterShape>>{std::move(shapes)};
}

Result<DexCallResultShape> call_result_shape(const Instruction &instruction, const DexMetadata *metadata) {
    if (!metadata || metadata->prototype_return_kinds.empty()) return DexCallResultShape{};
    const auto first = unit(instruction, 0);
    const auto op = static_cast<std::uint8_t>(first & 0xff);
    std::optional<std::uint32_t> proto_index;
    if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
        const auto method_index = unit(instruction, 1);
        if (method_index >= metadata->method_prototype_indices.size())
            return Error{ErrorCode::malformed, "DEX invoke method index is outside retained method metadata"};
        proto_index = metadata->method_prototype_indices[method_index];
    } else if (op == 0xfa || op == 0xfb) {
        proto_index = unit(instruction, 3);
    } else if (op == 0xfc || op == 0xfd) {
        const auto call_site_index = unit(instruction, 1);
        if (call_site_index >= metadata->call_sites.size())
            return Error{ErrorCode::malformed, "DEX invoke-custom call-site index is outside retained metadata"};
        const auto &site = metadata->call_sites[call_site_index];
        if (site.values.size() < 3 || site.values[2].type != 0x15 || site.values[2].payload > UINT32_MAX)
            return DexCallResultShape{};
        proto_index = static_cast<std::uint32_t>(site.values[2].payload);
    } else {
        return DexCallResultShape{};
    }
    if (*proto_index >= metadata->prototype_return_kinds.size())
        return Error{ErrorCode::malformed, "DEX invoke prototype index is outside retained metadata"};
    if (*proto_index < metadata->prototype_return_type_indices.size() && !metadata->type_descriptors.empty()) {
        const auto type_index = metadata->prototype_return_type_indices[*proto_index];
        if (type_index >= metadata->type_descriptors.size())
            return Error{ErrorCode::malformed, "DEX prototype return type is outside retained descriptor metadata"};
        if (metadata->type_descriptors[type_index] == "V") return DexCallResultShape{true, true, {}};
        auto type = dex_type_value(*metadata, type_index);
        if (!type) return type.error();
        return DexCallResultShape{true, false, type.value()};
    }
    switch (metadata->prototype_return_kinds[*proto_index]) {
    case DexReturnKind::void_value: return DexCallResultShape{true, true, {}};
    case DexReturnKind::integer32: return DexCallResultShape{true, false, i32()};
    case DexReturnKind::float32: return DexCallResultShape{true, false, f32()};
    case DexReturnKind::integer64: return DexCallResultShape{true, false, i64()};
    case DexReturnKind::float64: return DexCallResultShape{true, false, f64()};
    case DexReturnKind::reference: return DexCallResultShape{true, false, pointer32()};
    case DexReturnKind::unknown: return DexCallResultShape{};
    }
    return Error{ErrorCode::malformed, "DEX prototype has an invalid retained return kind"};
}

bool dex_invoke_opcode(std::uint8_t op) {
    return (op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78) ||
           (op >= 0xfa && op <= 0xfd);
}

Result<Statement> lift_one(const Instruction &instruction, const DexMetadata *metadata) {
    if (instruction.context.architecture != Architecture::dex || instruction.length < 2 ||
        instruction.length > instruction.bytes.size() || (instruction.length & 1))
        return Error{ErrorCode::unsupported, "DEX lifter received a non-Dalvik or malformed instruction"};
    const auto first = unit(instruction, 0);
    const auto op = static_cast<std::uint8_t>(first & 0xff);
    const auto hi = static_cast<std::uint8_t>(first >> 8);
    const auto expected_length = [&]() -> unsigned {
        if (op == 0x01 || op == 0x04 || op == 0x07) return 2;
        if (op == 0x02 || op == 0x05 || op == 0x08 || op == 0x13 || op == 0x15 ||
            op == 0x16 || op == 0x19) return 4;
        if (op == 0x03 || op == 0x06 || op == 0x09 || op == 0x14 || op == 0x17) return 6;
        if (op == 0x18) return 10;
        if (op == 0x1a || op == 0x1c || op == 0x1f || op == 0x20) return 4;
        if (op == 0x1b) return 6;
        if (op == 0x24 || op == 0x25 || op == 0x26) return 6;
        if (op == 0xfe || op == 0xff) return 4;
        if (op == 0xfa || op == 0xfb) return 8;
        if (op == 0xfc || op == 0xfd) return 6;
        if (op == 0x1d || op == 0x1e || op == 0x27) return 2;
        if (op == 0x2b || op == 0x2c) return 6;
        if (op >= 0x2d && op <= 0x31) return 4;
        if (op >= 0xa6 && op <= 0xaf) return 4;
        if (op >= 0xc6 && op <= 0xcf) return 2;
        if (op >= 0xd0 && op <= 0xe2) return 4;
        if (op >= 0x7b && op <= 0x8f) return 2;
        if ((op >= 0x44 && op <= 0x6d) || (op >= 0xe3 && op <= 0xeb) ||
            op == 0x23 || (op >= 0x6e && op <= 0x78))
            return op >= 0x6e && op <= 0x78 ? 6 : 4;
        if (op >= 0x9b && op <= 0xa5) return 4;
        if (op >= 0xbb && op <= 0xc5) return 2;
        return 0;
    }();
    if (expected_length && instruction.length != expected_length)
        return Error{ErrorCode::unsupported, "DEX instruction has an invalid encoded length"};
    auto require_reg = [&](std::uint16_t index) -> Result<RegisterOperand> {
        return vreg(index);
    };
    auto require_wide = [&](std::uint16_t index) -> Result<RegisterOperand> {
        // A Dalvik wide value occupies consecutive, non-overlapping 32-bit
        // slots. The common register operand stores the full 16-bit DEX index.
        if (index == UINT16_MAX)
            return Error{ErrorCode::unsupported, "DEX wide register pair exceeds the 16-bit register-index limit"};
        auto result = vreg(index);
        result.width = 64;
        return result;
    };
    const auto assign = [&](std::uint16_t dst, ExpressionPtr value) -> Result<Statement> {
        auto target = require_reg(dst);
        if (!target) return target.error();
        return Statement{Assign{target.value(), std::move(value)}};
    };
    if (op == 0x00 && hi == 0)
        return Statement{Intrinsic{"dex_nop", {}, IntrinsicMemoryEffect::none}};
    if (op >= 0x0a && op <= 0x0c) {
        const bool wide = op == 0x0b;
        const auto type = op == 0x0c ? pointer32() : unknown_type(wide ? 64 : 32);
        auto destination = wide ? require_wide(hi) : require_reg(hi);
        if (!destination) return destination.error();
        return Statement{Assign{destination.value(), unknown_value(type, "DEX invocation result without descriptor metadata")}};
    }
    if (op == 0x0d)
        return assign(hi, unknown_value(pointer32(), "DEX caught exception without handler type metadata"));
    if ((op >= 0x01 && op <= 0x03) || (op >= 0x07 && op <= 0x09)) {
        const bool object = op >= 0x07;
        std::uint16_t dst = 0, src = 0;
        const auto form = static_cast<unsigned>((op - 1) % 3);
        if (form == 0) { dst = hi & 15; src = hi >> 4; }
        else if (form == 1) { dst = hi; src = unit(instruction, 1); }
        else { dst = unit(instruction, 1); src = unit(instruction, 2); }
        auto source = require_reg(src);
        if (!source) return source.error();
        return assign(dst, object ? typed_reg(source.value(), pointer32()) : reg(source.value()));
    }
    if (op == 0x04 || op == 0x05 || op == 0x06) {
        std::uint16_t dst = 0, src = 0;
        if (op == 0x04) { dst = hi & 15; src = hi >> 4; }
        else if (op == 0x05) { dst = hi; src = unit(instruction, 1); }
        else { dst = unit(instruction, 1); src = unit(instruction, 2); }
        auto destination = require_wide(dst);
        auto source = require_wide(src);
        if (!destination) return destination.error();
        if (!source) return source.error();
        return Statement{Assign{destination.value(), wide_reg(source.value())}};
    }
    if (op >= 0x7b && op <= 0x8f) {
        const auto dst_index = static_cast<std::uint16_t>(hi & 15);
        const auto src_index = static_cast<std::uint16_t>(hi >> 4);
        const auto int_source = [&]() -> Result<ExpressionPtr> {
            auto source = require_reg(src_index);
            if (!source) return source.error();
            return reg(source.value());
        };
        const auto wide_source = [&](ValueType type) -> Result<ExpressionPtr> {
            auto source = require_wide(src_index);
            if (!source) return source.error();
            return typed_reg(source.value(), type);
        };
        const auto destination = [&](ValueType type) -> Result<RegisterOperand> {
            return type.bits == 64 ? require_wide(dst_index) : require_reg(dst_index);
        };
        auto emit_unary = [&](std::string operation, ExpressionPtr source, ValueType type) -> Result<Statement> {
            auto target = destination(type);
            if (!target) return target.error();
            return Statement{Assign{target.value(), unary(std::move(operation), std::move(source), type)}};
        };
        if (op == 0x7b || op == 0x7c) {
            auto source = int_source();
            if (!source) return source.error();
            return emit_unary(op == 0x7b ? "neg" : "bitnot", source.value(), i32());
        }
        if (op == 0x7d || op == 0x7e) {
            auto source = wide_source(i64());
            if (!source) return source.error();
            return emit_unary(op == 0x7d ? "neg" : "bitnot", source.value(), i64());
        }
        if (op == 0x7f) {
            auto source = require_reg(src_index);
            if (!source) return source.error();
            return emit_unary("neg", typed_reg(source.value(), f32()), f32());
        }
        if (op == 0x80) {
            auto source = wide_source(f64());
            if (!source) return source.error();
            return emit_unary("neg", source.value(), f64());
        }
        if (op >= 0x81 && op <= 0x8f) {
            std::string operation;
            ValueType input = i32(), output = i32();
            bool wide_input = false;
            switch (op) {
            case 0x81: operation = "sext32"; output = i64(); break;
            case 0x82: operation = "i2f"; output = f32(); break;
            case 0x83: operation = "i2d"; output = f64(); break;
            case 0x84: operation = "trunc32"; input = i64(); wide_input = true; break;
            case 0x85: operation = "l2f"; input = i64(); output = f32(); wide_input = true; break;
            case 0x86: operation = "l2d"; input = i64(); output = f64(); wide_input = true; break;
            case 0x87: operation = "f2i"; input = f32(); break;
            case 0x88: operation = "f2l"; input = f32(); output = i64(); break;
            case 0x89: operation = "f2d"; input = f32(); output = f64(); break;
            case 0x8a: operation = "d2i"; input = f64(); wide_input = true; break;
            case 0x8b: operation = "d2l"; input = f64(); output = i64(); wide_input = true; break;
            case 0x8c: operation = "d2f"; input = f64(); output = f32(); wide_input = true; break;
            case 0x8d: operation = "sext8"; break;
            case 0x8e: operation = "zext16"; break;
            case 0x8f: operation = "sext16"; break;
            default: return Error{ErrorCode::unsupported, "Unknown DEX conversion opcode"};
            }
            Result<ExpressionPtr> source = [&]() -> Result<ExpressionPtr> {
                if (wide_input) return wide_source(input);
                auto value = require_reg(src_index);
                if (!value) return value.error();
                return typed_reg(value.value(), input);
            }();
            if (!source) return source.error();
            if (op == 0x8d || op == 0x8e || op == 0x8f) {
                const auto narrowed_type = ValueType{TypeKind::integer, static_cast<std::uint16_t>(op == 0x8d ? 8 : 16), op != 0x8e};
                auto narrowed = unary("trunc" + std::to_string(narrowed_type.bits), source.value(), narrowed_type);
                return emit_unary(std::move(operation), std::move(narrowed), i32());
            }
            return emit_unary(std::move(operation), source.value(), output);
        }
    }
    if (op == 0x12) {
        const auto value = static_cast<std::int32_t>(static_cast<std::int8_t>(hi) >> 4);
        return assign(hi & 15, constant(static_cast<std::uint32_t>(value)));
    }
    if (op == 0x1a || op == 0x1b || op == 0xfe || op == 0xff) {
        const auto index = op == 0x1b
            ? std::uint32_t(unit(instruction, 1)) | (std::uint32_t(unit(instruction, 2)) << 16)
            : std::uint32_t(unit(instruction, 1));
        const auto description = op == 0xfe ? "DEX method-handle constant method_handle@" + std::to_string(index) :
            op == 0xff ? "DEX method-type constant proto@" + std::to_string(index) :
                         "DEX string constant string@" + std::to_string(index);
        return assign(hi, unknown_value(pointer32(), description));
    }
    if (op == 0x1c) {
        const auto type_index = unit(instruction, 1);
        auto valid = validate_type_descriptor(metadata, type_index, DexDescriptorConstraint::any,
                                              "const-class");
        if (!valid) return valid.error();
        return assign(hi, unknown_value(pointer32(), "DEX class constant type@" +
                                        std::to_string(type_index)));
    }
    if (op == 0x1f) {
        auto valid = validate_type_descriptor(metadata, unit(instruction, 1),
                                              DexDescriptorConstraint::any, "check-cast");
        if (!valid) return valid.error();
        auto object = require_reg(hi);
        if (!object) return object.error();
        return Statement{Intrinsic{"dex_check_cast_type@" + std::to_string(unit(instruction, 1)),
            {typed_reg(object.value(), pointer32())}, IntrinsicMemoryEffect::unknown}};
    }
    if (op == 0x20) {
        auto valid = validate_type_descriptor(metadata, unit(instruction, 1),
                                              DexDescriptorConstraint::any, "instance-of");
        if (!valid) return valid.error();
        const auto destination_index = static_cast<std::uint16_t>(hi & 15);
        auto destination = require_reg(destination_index);
        auto object = require_reg(hi >> 4);
        if (!destination) return destination.error();
        if (!object) return object.error();
        const ValueType boolean_type{TypeKind::boolean, 1, false};
        Intrinsic result;
        result.name = "dex_instance_of_type@" + std::to_string(unit(instruction, 1));
        result.operands = {typed_reg(object.value(), pointer32())};
        result.memory_effect = IntrinsicMemoryEffect::read;
        result.register_writes.push_back(destination.value());
        result.register_output_values.push_back(unknown_value(boolean_type, "DEX runtime type-test result"));
        result.result_type = boolean_type;
        return Statement{std::move(result)};
    }
    if (op == 0x1d || op == 0x1e || op == 0x27) {
        auto object = require_reg(hi);
        if (!object) return object.error();
        const char *name = op == 0x1d ? "dex_monitor_enter" : op == 0x1e ? "dex_monitor_exit" : "dex_throw";
        return Statement{Intrinsic{name, {typed_reg(object.value(), pointer32())}, IntrinsicMemoryEffect::unknown}};
    }
    if (op == 0x13 || op == 0x14 || op == 0x15) {
        const auto value = op == 0x13
            ? static_cast<std::uint32_t>(static_cast<std::int32_t>(std::bit_cast<std::int16_t>(unit(instruction, 1))))
            : op == 0x15
                ? std::uint32_t(unit(instruction, 1)) << 16
                : std::uint32_t(unit(instruction, 1)) |
                    (std::uint32_t(unit(instruction, 2)) << 16);
        return assign(hi, constant(value));
    }
    if (op >= 0x16 && op <= 0x19) {
        std::uint64_t value = 0;
        if (op == 0x16) value = static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int16_t>(unit(instruction, 1))));
        else if (op == 0x17) {
            const auto bits = std::uint32_t(unit(instruction, 1)) | (std::uint32_t(unit(instruction, 2)) << 16);
            value = static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(bits)));
        } else if (op == 0x18) {
            value = std::uint64_t(unit(instruction, 1)) | (std::uint64_t(unit(instruction, 2)) << 16) |
                (std::uint64_t(unit(instruction, 3)) << 32) | (std::uint64_t(unit(instruction, 4)) << 48);
        } else {
            value = static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int16_t>(unit(instruction, 1)))) << 48;
        }
        auto destination = require_wide(hi);
        if (!destination) return destination.error();
        return Statement{Assign{destination.value(), wide_constant(value)}};
    }
    if ((op >= 0x90 && op <= 0x9a) || (op >= 0xb0 && op <= 0xba)) {
        static constexpr std::array<const char *, 11> operations{
            "add", "sub", "mul", "sdiv", "srem", "and", "or", "xor", "shl", "sar", "shr"};
        const auto slot = static_cast<unsigned>((op >= 0xb0 ? op - 0xb0 : op - 0x90));
        std::uint16_t dst = hi, left = hi, right = 0;
        if (op >= 0xb0) { dst = hi & 15; left = dst; right = hi >> 4; }
        else { const auto rhs = unit(instruction, 1); right = rhs & 0xff; }
        auto lhs_reg = require_reg(left);
        auto rhs_reg = require_reg(right);
        if (!lhs_reg) return lhs_reg.error();
        if (!rhs_reg) return rhs_reg.error();
        auto right_value = reg(rhs_reg.value());
        if (slot >= 8)
            right_value = binary("and", std::move(right_value), constant(31));
        return assign(dst, binary(operations[slot], reg(lhs_reg.value()), std::move(right_value)));
    }
    if (op >= 0xd0 && op <= 0xe2) {
        static constexpr std::array<const char *, 8> literal16_operations{
            "add", "sub", "mul", "sdiv", "srem", "and", "or", "xor"};
        static constexpr std::array<const char *, 11> literal8_operations{
            "add", "sub", "mul", "sdiv", "srem", "and", "or", "xor", "shl", "sar", "shr"};
        const bool literal16 = op <= 0xd7;
        const auto slot = static_cast<unsigned>(literal16 ? op - 0xd0 : op - 0xd8);
        const auto packed = literal16 ? static_cast<std::uint16_t>(hi) : unit(instruction, 1);
        const auto destination_index = static_cast<std::uint16_t>(literal16 ? packed & 15 : hi);
        const auto source_index = static_cast<std::uint16_t>(literal16 ? packed >> 4 : packed & 0xff);
        const auto immediate = literal16
            ? static_cast<std::int32_t>(std::bit_cast<std::int16_t>(unit(instruction, 1)))
            : static_cast<std::int32_t>(std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(packed >> 8)));
        auto source = require_reg(source_index);
        if (!source) return source.error();
        ExpressionPtr literal = constant(static_cast<std::uint32_t>(immediate));
        ExpressionPtr left = reg(source.value());
        ExpressionPtr right = std::move(literal);
        const auto operation = literal16 ? literal16_operations[slot] : literal8_operations[slot];
        if (slot == 1) {
            std::swap(left, right); // rsub computes literal - vB
        } else if (!literal16 && slot >= 8) {
            right = binary("and", std::move(right), constant(31));
        }
        return assign(destination_index, binary(operation, std::move(left), std::move(right)));
    }
    // The optimized ODEX return-void-barrier has the same control-flow result
    // as the standard return-void opcode; the barrier is a runtime scheduling
    // detail that the shared IR does not represent separately.
    if (op == 0x0e || op == 0xf1) return Statement{Return{}};
    if (op == 0x2b || op == 0x2c) {
        if (!instruction.dex_switch || !instruction.dex_switch->validated ||
            instruction.flow != FlowKind::switch_dispatch)
            return Error{ErrorCode::unsupported, "DEX switch payload is unavailable or unvalidated"};
        return Statement{Intrinsic{"dex_switch_dispatch", {reg(vreg(hi))}, IntrinsicMemoryEffect::none}};
    }
    if (op >= 0x2d && op <= 0x31) {
        static constexpr std::array<const char *, 5> names{
            "dex_cmpl_float", "dex_cmpg_float", "dex_cmpl_double", "dex_cmpg_double", "dex_cmp_long"};
        const auto destination_index = static_cast<std::uint16_t>(hi);
        const auto packed = unit(instruction, 1);
        const auto left_index = static_cast<std::uint16_t>(packed & 0xff);
        const auto right_index = static_cast<std::uint16_t>(packed >> 8);
        const bool is_wide = op >= 0x2f;
        const auto input_type = op <= 0x2e ? f32() : op <= 0x30 ? f64() : i64();
        auto left_operand = is_wide ? require_wide(left_index) : require_reg(left_index);
        auto right_operand = is_wide ? require_wide(right_index) : require_reg(right_index);
        auto destination = require_reg(destination_index);
        if (!left_operand) return left_operand.error();
        if (!right_operand) return right_operand.error();
        if (!destination) return destination.error();
        Intrinsic compare;
        compare.name = names[op - 0x2d];
        compare.operands = {typed_reg(left_operand.value(), input_type),
                            typed_reg(right_operand.value(), input_type)};
        compare.memory_effect = IntrinsicMemoryEffect::none;
        compare.register_writes.push_back(destination.value());
        compare.result_type = i32();
        return Statement{std::move(compare)};
    }
    if (op == 0x0f || op == 0x11) {
        auto source = require_reg(hi);
        if (!source) return source.error();
        return Statement{Return{op == 0x11 ? typed_reg(source.value(), pointer32()) : reg(source.value())}};
    }
    if (op == 0x10) {
        auto source = require_wide(hi);
        if (!source) return source.error();
        return Statement{Return{wide_reg(source.value())}};
    }
    if ((op >= 0xa6 && op <= 0xaf) || (op >= 0xc6 && op <= 0xcf)) {
        static constexpr std::array<const char *, 5> operations{
            "+", "-", "*", "/", "frem"};
        const bool two_address = op >= 0xc6;
        const auto normalized = static_cast<unsigned>(two_address ? op - 0xc6 : op - 0xa6);
        const bool is_double = normalized >= 5;
        const auto operation_index = normalized % 5;
        const auto destination_index = static_cast<std::uint16_t>(
            two_address ? hi & 15 : hi);
        const auto left_index = static_cast<std::uint16_t>(
            two_address ? destination_index : unit(instruction, 1) & 0xff);
        const auto right_index = static_cast<std::uint16_t>(
            two_address ? hi >> 4 : unit(instruction, 1) >> 8);
        const auto type = is_double ? f64() : f32();
        const auto make_register = [&](std::uint16_t index) -> Result<ExpressionPtr> {
            auto operand = is_double ? require_wide(index) : require_reg(index);
            if (!operand) return operand.error();
            return typed_reg(operand.value(), type);
        };
        auto destination = is_double ? require_wide(destination_index) : require_reg(destination_index);
        if (!destination) return destination.error();
        auto left = make_register(left_index);
        auto right = make_register(right_index);
        if (!left) return left.error();
        if (!right) return right.error();
        auto value = std::make_shared<Expression>(Expression{type, BinaryValue{
            operations[operation_index], std::move(left.value()), std::move(right.value())}});
        return Statement{Assign{destination.value(), std::move(value)}};
    }
    if ((op >= 0x9b && op <= 0xa5) || (op >= 0xbb && op <= 0xc5)) {
        static constexpr std::array<const char *, 11> operations{
            "add", "sub", "mul", "sdiv", "srem", "and", "or", "xor", "shl", "sar", "shr"};
        const auto slot = static_cast<unsigned>(op >= 0xbb ? op - 0xbb : op - 0x9b);
        const bool two_address = op >= 0xbb;
        const auto dst = two_address ? static_cast<std::uint16_t>(hi & 15) : static_cast<std::uint16_t>(hi);
        const auto operands = two_address ? std::uint16_t(hi >> 4) : unit(instruction, 1);
        const auto left = two_address ? dst : static_cast<std::uint16_t>(operands & 0xff);
        const auto right = static_cast<std::uint16_t>(two_address ? operands : operands >> 8);
        auto destination = require_wide(dst);
        auto lhs = require_wide(left);
        if (!destination) return destination.error();
        if (!lhs) return lhs.error();
        ExpressionPtr rhs_value;
        if (slot >= 8) {
            auto rhs = require_reg(right); // long shifts take an int count, not a wide operand
            if (!rhs) return rhs.error();
            rhs_value = binary("and", reg(rhs.value()), constant(63));
        } else {
            auto rhs = require_wide(right);
            if (!rhs) return rhs.error();
            rhs_value = wide_reg(rhs.value());
        }
        return Statement{Assign{destination.value(), wide_binary(operations[slot], wide_reg(lhs.value()), std::move(rhs_value))}};
    }
    const auto dex_value_type = [](unsigned kind) {
        switch (kind) {
        case 1: return unknown_type(64);
        case 2: return pointer32();
        case 3: return ValueType{TypeKind::boolean, 1, false};
        case 4: case 6: return ValueType{TypeKind::integer, 32, true};
        case 5: return ValueType{TypeKind::integer, 32, false};
        default: return unknown_type(32);
        }
    };
    const auto field_descriptor_type = [&](unsigned kind, std::uint16_t field_index)
        -> Result<ValueType> {
        if (!metadata) return dex_value_type(kind);
        if (field_index >= metadata->field_identifiers.size())
            return Error{ErrorCode::malformed, "DEX field index is outside retained identifier metadata"};
        const auto &field = metadata->field_identifiers[field_index];
        if (field.type_index >= metadata->type_descriptors.size())
            return Error{ErrorCode::malformed, "DEX field type index is outside retained type metadata"};
        const auto &descriptor = metadata->type_descriptors[field.type_index];
        ValueType type;
        bool matches_opcode = false;
        if (descriptor == "I") { type = i32(); matches_opcode = kind == 0; }
        else if (descriptor == "J") { type = i64(); matches_opcode = kind == 1; }
        else if (!descriptor.empty() && (descriptor[0] == 'L' || descriptor[0] == '[')) {
            type = pointer32(); matches_opcode = kind == 2;
        } else if (descriptor == "Z") {
            type = boolean_type(); matches_opcode = kind == 3;
        } else if (descriptor == "B") {
            type = ValueType{TypeKind::integer, 32, true}; matches_opcode = kind == 4;
        } else if (descriptor == "C") {
            type = ValueType{TypeKind::integer, 32, false}; matches_opcode = kind == 5;
        } else if (descriptor == "S") {
            type = ValueType{TypeKind::integer, 32, true}; matches_opcode = kind == 6;
        } else if (descriptor == "F") {
            type = f32(); matches_opcode = kind == 0;
        } else if (descriptor == "D") {
            type = f64(); matches_opcode = kind == 1;
        } else {
            return Error{ErrorCode::malformed, "DEX field has an invalid or unsupported type descriptor"};
        }
        if (!matches_opcode)
            return Error{ErrorCode::malformed, "DEX field descriptor disagrees with the field opcode variant"};
        return type;
    };
    const auto emit_memory_result = [&](std::string name, std::vector<ExpressionPtr> operands,
                                        std::uint16_t destination_index, ValueType type,
                                        IntrinsicMemoryEffect memory) -> Result<Statement> {
        auto destination = type.bits == 64 ? require_wide(destination_index) : require_reg(destination_index);
        if (!destination) return destination.error();
        Intrinsic effect;
        effect.name = std::move(name);
        effect.operands = std::move(operands);
        effect.memory_effect = memory;
        effect.register_writes.push_back(destination.value());
        effect.register_output_values.push_back(unknown_value(type, "unresolved DEX memory value"));
        effect.result_type = type;
        return Statement{std::move(effect)};
    };
    if (op == 0x21) {
        const auto destination_index = static_cast<std::uint16_t>(hi & 15);
        auto array = require_reg(hi >> 4);
        if (!array) return array.error();
        return emit_memory_result("dex_array_length", {typed_reg(array.value(), pointer32())},
                                  destination_index, i32(), IntrinsicMemoryEffect::read);
    }
    if (op == 0x22 || op == 0x23) {
        auto valid = validate_type_descriptor(metadata, unit(instruction, 1),
            op == 0x23 ? DexDescriptorConstraint::array_type : DexDescriptorConstraint::class_type,
            op == 0x23 ? "new-array" : "new-instance");
        if (!valid) return valid.error();
        const auto destination_index = static_cast<std::uint16_t>(op == 0x22 ? hi : (hi & 15));
        auto destination = require_reg(destination_index);
        if (!destination) return destination.error();
        Intrinsic allocation;
        allocation.name = op == 0x22 ? "dex_new_instance type@" + std::to_string(unit(instruction, 1))
                                     : "dex_new_array type@" + std::to_string(unit(instruction, 1));
        allocation.memory_effect = IntrinsicMemoryEffect::unknown;
        allocation.register_writes.push_back(destination.value());
        allocation.register_output_values.push_back(unknown_value(pointer32(), "DEX allocation result"));
        allocation.result_type = pointer32();
        if (op == 0x23) {
            auto size = require_reg(hi >> 4);
            if (!size) return size.error();
            allocation.operands.push_back(reg(size.value()));
        }
        return Statement{std::move(allocation)};
    }
    if (op == 0x24 || op == 0x25) {
        const bool range = op == 0x25;
        const auto count = static_cast<unsigned>(range ? hi : ((first >> 12) & 15));
        const auto type_index = unit(instruction, 1);
        auto element_type = unknown_type(32);
        if (metadata) {
            if (type_index >= metadata->type_descriptors.size())
                return Error{ErrorCode::malformed, "DEX filled-new-array type index is outside retained type metadata"};
            const auto &descriptor = metadata->type_descriptors[type_index];
            if (descriptor.size() < 2 || descriptor.front() != '[')
                return Error{ErrorCode::malformed, "DEX filled-new-array type is not an array descriptor"};
            const std::string_view component(descriptor.data() + 1, descriptor.size() - 1);
            if (component == "J" || component == "D")
                return Error{ErrorCode::malformed, "DEX filled-new-array cannot initialize a wide-element array"};
            if (component == "Z") element_type = boolean_type();
            else if (component == "B" || component == "S")
                element_type = ValueType{TypeKind::integer, 32, true};
            else if (component == "C") element_type = ValueType{TypeKind::integer, 32, false};
            else if (component == "I") element_type = i32();
            else if (component == "F") element_type = f32();
            else if (component.front() == '[' || component.front() == 'L') element_type = pointer32();
            else return Error{ErrorCode::malformed, "DEX filled-new-array component descriptor is unsupported"};
        }
        std::vector<ExpressionPtr> elements;
        elements.reserve(count + 1);
        elements.push_back(constant(type_index));
        if (range) {
            const auto start = static_cast<unsigned>(unit(instruction, 2));
            if (count && std::uint64_t(start) + count > std::uint64_t(UINT16_MAX) + 1)
                return Error{ErrorCode::malformed, "DEX filled-new-array/range exceeds the 16-bit register-index limit"};
            for (unsigned i = 0; i < count; ++i) {
                auto element = require_reg(static_cast<std::uint16_t>(start + i));
                if (!element) return element.error();
                elements.push_back(typed_reg(element.value(), element_type));
            }
        } else {
            const auto packed = unit(instruction, 2);
            const std::array<unsigned, 5> registers{unsigned(packed & 15), unsigned((packed >> 4) & 15),
                unsigned((packed >> 8) & 15), unsigned((packed >> 12) & 15), unsigned((first >> 8) & 15)};
            if (count > registers.size())
                return Error{ErrorCode::malformed, "DEX filled-new-array register count exceeds five"};
            for (unsigned i = 0; i < count; ++i) {
                auto element = require_reg(static_cast<std::uint16_t>(registers[i]));
                if (!element) return element.error();
                elements.push_back(typed_reg(element.value(), element_type));
            }
        }
        return Statement{Intrinsic{"dex_filled_new_array_type@" + std::to_string(type_index),
            std::move(elements), IntrinsicMemoryEffect::unknown}};
    }
    if (op == 0x26) {
        if (instruction.address.offset > UINT32_MAX)
            return Error{ErrorCode::malformed, "DEX array-data instruction exceeds the method address space"};
        auto array = require_reg(hi);
        if (!array) return array.error();
        const auto units = std::bit_cast<std::int32_t>(std::uint32_t(unit(instruction, 1)) |
            (std::uint32_t(unit(instruction, 2)) << 16));
        const auto delta = static_cast<std::int64_t>(units) * 2;
        std::uint64_t payload_offset = 0;
        if (delta >= 0) {
            const auto amount = static_cast<std::uint64_t>(delta);
            if (instruction.address.offset > UINT32_MAX || amount > UINT32_MAX - instruction.address.offset)
                return Error{ErrorCode::malformed, "DEX array-data payload target exceeds the method address space"};
            payload_offset = instruction.address.offset + amount;
        } else {
            const auto amount = static_cast<std::uint64_t>(-(delta + 1)) + 1;
            if (amount > instruction.address.offset)
                return Error{ErrorCode::malformed, "DEX array-data payload target precedes the method address space"};
            payload_offset = instruction.address.offset - amount;
        }
        if (payload_offset & 3)
            return Error{ErrorCode::malformed, "DEX array-data payload is not four-byte aligned"};
        return Statement{Intrinsic{"dex_fill_array_data_payload@" + std::to_string(payload_offset),
            {typed_reg(array.value(), pointer32())}, IntrinsicMemoryEffect::write}};
    }
    if ((op >= 0x44 && op <= 0x51) || (op >= 0x52 && op <= 0x6d) ||
        (op >= 0xe3 && op <= 0xeb)) {
        const bool array = op <= 0x51;
        const bool volatile_field = op >= 0xe3 && op <= 0xeb;
        bool load = false;
        unsigned kind = 0;
        std::uint16_t value_index = 0;
        std::vector<ExpressionPtr> operands;
        std::string name;
        IntrinsicMemoryEffect memory = IntrinsicMemoryEffect::read;
        if (array) {
            load = op <= 0x4a;
            kind = load ? static_cast<unsigned>(op - 0x44) : static_cast<unsigned>(op - 0x4b);
            value_index = hi;
            const auto packed = unit(instruction, 1);
            auto object = require_reg(packed & 255);
            auto index = require_reg(packed >> 8);
            if (!object) return object.error();
            if (!index) return index.error();
            operands.push_back(typed_reg(object.value(), pointer32()));
            operands.push_back(reg(index.value()));
            name = "dex_" + std::string(load ? "aget" : "aput") + "_kind" + std::to_string(kind);
        } else {
            const bool instance = volatile_field
                ? (op == 0xe3 || op == 0xe4 || op == 0xe7 || op == 0xe8 || op == 0xe9)
                : op < 0x60;
            if (instance) {
                if (volatile_field) {
                    load = op == 0xe3 || op == 0xe7 || op == 0xe8;
                    kind = op == 0xe7 ? 2u : (op == 0xe8 || op == 0xe9 ? 1u : 0u);
                } else {
                    load = op <= 0x58;
                    kind = load ? static_cast<unsigned>(op - 0x52) : static_cast<unsigned>(op - 0x59);
                }
                value_index = hi & 15;
                auto object = require_reg(hi >> 4);
                if (!object) return object.error();
                operands.push_back(typed_reg(object.value(), pointer32()));
            } else {
                if (volatile_field) {
                    load = op == 0xe5 || op == 0xea;
                    kind = op == 0xea || op == 0xeb ? 1u : 0u;
                } else {
                    load = op <= 0x66;
                    kind = load ? static_cast<unsigned>(op - 0x60) : static_cast<unsigned>(op - 0x67);
                }
                value_index = hi;
            }
            operands.push_back(constant(unit(instruction, 1)));
            name = "dex_" + std::string(instance ? (load ? "iget" : "iput") : (load ? "sget" : "sput")) +
                   (volatile_field ? "_volatile" : "") +
                   "_kind" + std::to_string(kind) + "_field@" + std::to_string(unit(instruction, 1));
        }
        auto type_result = array || volatile_field
            ? Result<ValueType>{dex_value_type(kind)}
            : field_descriptor_type(kind, unit(instruction, 1));
        if (!type_result) return type_result.error();
        const auto type = type_result.value();
        if (load)
            return emit_memory_result(std::move(name), std::move(operands), value_index, type,
                                      IntrinsicMemoryEffect::read);
        auto value = type.bits == 64 ? require_wide(value_index) : require_reg(value_index);
        if (!value) return value.error();
        operands.insert(operands.begin(), typed_reg(value.value(), type));
        Intrinsic store;
        store.name = std::move(name);
        store.operands = std::move(operands);
        store.memory_effect = IntrinsicMemoryEffect::write;
        return Statement{std::move(store)};
    }
    if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78) ||
        (op >= 0xfa && op <= 0xfd)) {
        static constexpr std::array<const char *, 5> names{
            "virtual", "super", "direct", "static", "interface"};
        const bool invoke_ext = op >= 0xfa;
        const bool polymorphic = op == 0xfa || op == 0xfb;
        const bool range = op >= 0x74 && op <= 0x78 || op == 0xfb || op == 0xfd;
        const auto kind = static_cast<unsigned>(range ? op - 0x74 : op - 0x6e);
        const auto method_index = unit(instruction, 1);
        std::vector<ExpressionPtr> arguments;
        std::uint32_t count = 0;
        std::uint32_t first_register = 0;
        std::array<std::uint32_t, 5> listed{};
        if (range) {
            count = hi;
            first_register = unit(instruction, 2);
            if (count && std::uint64_t(first_register) + count > std::uint64_t(UINT16_MAX) + 1)
                return Error{ErrorCode::unsupported, "DEX invoke/range register span exceeds the 16-bit register-index limit"};
        } else {
            count = (first >> 12) & 15;
            if (count > listed.size())
                return Error{ErrorCode::unsupported, "DEX invoke argument count exceeds the encoded five-register form"};
            const auto packed = unit(instruction, 2);
            listed = {std::uint32_t(packed & 15), std::uint32_t((packed >> 4) & 15),
                      std::uint32_t((packed >> 8) & 15), std::uint32_t((packed >> 12) & 15),
                      std::uint32_t((first >> 8) & 15)};
        }
        std::vector<std::uint16_t> argument_registers;
        argument_registers.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
            argument_registers.push_back(static_cast<std::uint16_t>(range ? first_register + i : listed[i]));
        auto signature = call_parameter_shapes(instruction, metadata);
        if (!signature) return signature.error();
        arguments.reserve(count + 1);
        if (signature.value()) {
            std::uint32_t expected_words = 0;
            for (const auto &parameter : *signature.value()) expected_words += parameter.words;
            if (expected_words != count)
                return Error{ErrorCode::malformed, "DEX invoke register-word count does not match its prototype"};
            std::size_t cursor = 0;
            for (const auto &parameter : *signature.value()) {
                if (parameter.words == 2) {
                    if (cursor + 1 >= argument_registers.size() || argument_registers[cursor] == UINT16_MAX ||
                        argument_registers[cursor + 1] != argument_registers[cursor] + 1)
                        return Error{ErrorCode::malformed, "DEX wide invoke argument does not use an adjacent register pair"};
                    auto argument = require_wide(argument_registers[cursor]);
                    if (!argument) return argument.error();
                    arguments.push_back(typed_reg(argument.value(), parameter.type));
                    cursor += 2;
                } else {
                    if (cursor >= argument_registers.size())
                        return Error{ErrorCode::malformed, "DEX invoke prototype consumes more words than encoded"};
                    auto argument = require_reg(argument_registers[cursor++]);
                    if (!argument) return argument.error();
                    arguments.push_back(typed_reg(argument.value(), parameter.type));
                }
            }
            if (cursor != argument_registers.size())
                return Error{ErrorCode::malformed, "DEX invoke prototype does not consume all encoded argument words"};
        } else {
            for (const auto index : argument_registers) {
                auto argument = require_reg(index);
                if (!argument) return argument.error();
                arguments.push_back(typed_reg(argument.value(), unknown_type(32)));
            }
        }
        Intrinsic call;
        if (invoke_ext) {
            call.name = polymorphic ? "dex_invoke_polymorphic_method@" + std::to_string(method_index) +
                                      "_proto@" + std::to_string(unit(instruction, 3))
                                    : "dex_invoke_custom_callsite@" + std::to_string(method_index);
        } else {
            call.name = "dex_invoke_" + std::string(names[kind]) + "_method@" + std::to_string(method_index);
        }
        call.operands = std::move(arguments);
        call.memory_effect = IntrinsicMemoryEffect::unknown;
        return Statement{std::move(call)};
    }
    if (op >= 0x28 && op <= 0x2a)
        return Statement{Branch{"true", instruction.direct_target, {}}};
    if (op >= 0x32 && op <= 0x3d) {
        static constexpr std::array<const char *, 6> comparisons{"eq", "ne", "slt", "sge", "sgt", "sle"};
        const auto slot = static_cast<unsigned>(op <= 0x37 ? op - 0x32 : op - 0x38);
        const auto left_index = static_cast<std::uint16_t>(op <= 0x37 ? hi & 15 : hi);
        auto left = require_reg(left_index);
        if (!left) return left.error();
        ExpressionPtr right;
        if (op <= 0x37) {
            auto rhs = require_reg(hi >> 4);
            if (!rhs) return rhs.error();
            right = reg(rhs.value());
        } else right = constant(0);
        return Statement{Branch{"predicate", instruction.direct_target, {},
            predicate(comparisons[slot], reg(left.value()), std::move(right))}};
    }
    return Error{ErrorCode::unsupported,
        "DEX opcode/effect is not modeled by the current Dalvik lifter (opcode " + std::to_string(op) + ")"};
}
}

Result<LiftedFunction> lift_dex_function(const FunctionRecord &function, const FunctionSnapshot &snapshot,
                                         const DexMetadata *metadata) {
    std::map<std::uint64_t, std::shared_ptr<const BasicBlock>> available;
    for (const auto &block : snapshot.blocks) {
        if (!block) return Error{ErrorCode::invalid_argument, "DEX function snapshot contains a null block"};
        if (!available.emplace(block->id.value, block).second)
            return Error{ErrorCode::invalid_argument, "DEX function snapshot has duplicate block IDs"};
    }
    LiftedFunction result{function.id, function.entry, {}, {}};
    if (function.blocks.size() > 1'000'000)
        return Error{ErrorCode::resource_limit, "DEX function exceeds the lifting block budget"};
    std::optional<std::uint32_t> declared_register_count;
    if (metadata && function.entry.space.value != 0 && function.entry.space.value - 1 <= UINT32_MAX) {
        const auto method_index = static_cast<std::uint32_t>(function.entry.space.value - 1);
        const auto method = std::lower_bound(metadata->code.begin(), metadata->code.end(), method_index,
            [](const DexMethodCode &candidate, std::uint32_t index) { return candidate.method_index < index; });
        if (method != metadata->code.end() && method->method_index == method_index)
            declared_register_count = method->register_count;
    }
    result.blocks.reserve(function.blocks.size());
    std::set<std::pair<std::uint64_t, std::uint64_t>> block_entries;
    for (const auto id : function.blocks) {
        const auto found = available.find(id.value);
        if (found == available.end()) return Error{ErrorCode::invalid_argument, "DEX function references a missing block"};
        block_entries.emplace(found->second->begin.space.value, found->second->begin.offset);
    }
    std::uint64_t instruction_count = 0;
    for (const auto id : function.blocks) {
        const auto found = available.find(id.value);
        if (found == available.end()) return Error{ErrorCode::invalid_argument, "DEX function references a missing block"};
        const auto &source = *found->second;
        LiftedBlock block{id, source.begin, {}, source.successors};
        if (source.instructions.size() > 10'000'000 - instruction_count)
            return Error{ErrorCode::resource_limit, "DEX function exceeds the lifting instruction budget"};
        instruction_count += source.instructions.size();
        block.instructions.reserve(source.instructions.size());
        const Instruction *previous_instruction = nullptr;
        for (const auto &fact : source.instructions) {
            if (!fact) return Error{ErrorCode::invalid_argument, "DEX block contains a null instruction fact"};
            const auto &instruction = fact->instruction;
            if (declared_register_count) {
                for (const auto &operand : instruction.operands) {
                    const auto *reg = std::get_if<RegisterOperand>(&operand);
                    if (!reg || reg->bank != RegisterBank::dex_vreg) continue;
                    const std::uint32_t slots = reg->width > 32 ? 2 : 1;
                    if (reg->index >= *declared_register_count ||
                        slots > *declared_register_count - reg->index)
                        return Error{ErrorCode::malformed,
                            "DEX register operand exceeds the method's declared register file"};
                }
            }
            if (instruction.opcode == Opcode::dex_switch && fact != source.instructions.back())
                return Error{ErrorCode::malformed, "DEX switch is not the final instruction in its basic block"};
            auto statement = lift_one(instruction, metadata);
            if (!statement)
                return Error{statement.error().code, "at method-relative 0x" + [&] {
                    constexpr char hex[] = "0123456789abcdef";
                    std::string out;
                    auto value = instruction.address.offset;
                    do { out.push_back(hex[value & 15]); value >>= 4; } while (value);
                    std::reverse(out.begin(), out.end());
                    return out;
                }() + ": " + statement.error().message};
            // Resolve DEX string constants through the loader's retained string
            // table. Loading a constant can perform runtime resolution, so keep
            // the memory effect explicit while preserving a bounded preview.
            const auto opcode = static_cast<std::uint8_t>(unit(instruction, 0) & 0xff);
            if (metadata && (opcode == 0x1a || opcode == 0x1b)) {
                const auto string_index = opcode == 0x1a
                    ? static_cast<std::uint32_t>(unit(instruction, 1))
                    : static_cast<std::uint32_t>(unit(instruction, 1)) |
                        (static_cast<std::uint32_t>(unit(instruction, 2)) << 16);
                if (string_index >= metadata->strings.size())
                    return Error{ErrorCode::malformed, "DEX const-string index is outside retained string metadata"};
                Intrinsic load;
                load.name = "dex_string_constant #" + std::to_string(string_index) + " \"" +
                    string_constant_preview(metadata->strings[string_index]) + "\"";
                load.memory_effect = IntrinsicMemoryEffect::unknown;
                const RegisterOperand destination{RegisterBank::dex_vreg,
                    static_cast<std::uint8_t>(unit(instruction, 0) >> 8), 32, false};
                load.register_writes.push_back(destination);
                load.register_output_values.push_back(unknown_value(pointer32(), load.name));
                load.result_type = pointer32();
                statement.value() = Statement{std::move(load)};
            }
            // Dalvik integer division and remainder throw ArithmeticException
            // exactly when the divisor is zero. Preserve that exceptional edge
            // alongside the normal arithmetic result in the lifted block.
            const auto first = unit(instruction, 0);
            const auto op = static_cast<std::uint8_t>(first & 0xff);
            if (op >= 0x0a && op <= 0x0c) {
                if (!previous_instruction || previous_instruction->address.space.value != instruction.address.space.value ||
                    previous_instruction->address.offset > UINT64_MAX - previous_instruction->length ||
                    previous_instruction->address.offset + previous_instruction->length != instruction.address.offset)
                    return Error{ErrorCode::malformed, "DEX move-result is not immediately adjacent to a result producer in the same basic block"};
                const auto previous_op = static_cast<std::uint8_t>(unit(*previous_instruction, 0) & 0xff);
                const bool filled_array = previous_op == 0x24 || previous_op == 0x25;
                if (filled_array) {
                    if (op != 0x0c)
                        return Error{ErrorCode::malformed, "DEX filled-new-array must be followed by move-result-object"};
                    if (block.instructions.empty() || block.instructions.back().origin.address != previous_instruction->address)
                        return Error{ErrorCode::malformed, "DEX move-result-object cannot be linked to the preceding filled-new-array"};
                    auto *allocation = std::get_if<Intrinsic>(&block.instructions.back().statement);
                    if (!allocation || !allocation->name.starts_with("dex_filled_new_array_type@"))
                        return Error{ErrorCode::malformed, "DEX filled-new-array did not lift to a result-bearing intrinsic"};
                    const auto destination_index = static_cast<std::uint16_t>(first >> 8);
                    const RegisterOperand destination{RegisterBank::dex_vreg,
                        destination_index, 32, false};
                    allocation->register_writes.push_back(destination);
                    allocation->register_output_values.push_back(unknown_value(pointer32(),
                        "DEX filled-new-array result with unresolved element type"));
                    allocation->result_type = pointer32();
                    statement.value() = Statement{Intrinsic{"dex_move_result_link", {}, IntrinsicMemoryEffect::none}};
                } else if (dex_invoke_opcode(previous_op)) {
                    auto shape = call_result_shape(*previous_instruction, metadata);
                    if (!shape) return shape.error();
                    if (shape.value().known) {
                        const bool matches = op == 0x0a
                            ? (shape.value().type.kind == TypeKind::integer || shape.value().type.kind == TypeKind::floating ||
                               shape.value().type.kind == TypeKind::boolean) && shape.value().type.bits <= 32
                            : op == 0x0b ? shape.value().type.bits == 64
                            : shape.value().type.kind == TypeKind::pointer && shape.value().type.bits == 32;
                        if (shape.value().is_void || !matches)
                            return Error{ErrorCode::malformed, "DEX move-result variant does not match the invoked prototype return type"};
                        if (block.instructions.empty() || block.instructions.back().origin.address != previous_instruction->address)
                            return Error{ErrorCode::malformed, "DEX move-result cannot be linked to the preceding invoke statement"};
                        auto *call = std::get_if<Intrinsic>(&block.instructions.back().statement);
                        if (!call)
                            return Error{ErrorCode::malformed, "DEX invoke did not lift to a result-bearing intrinsic"};
                        const auto destination_index = static_cast<std::uint16_t>(first >> 8);
                        if (shape.value().type.bits == 64 && destination_index == UINT16_MAX)
                            return Error{ErrorCode::malformed, "DEX wide move-result register pair exceeds the 16-bit register-index limit"};
                        const RegisterOperand destination{RegisterBank::dex_vreg,
                            destination_index,
                            static_cast<std::uint16_t>(shape.value().type.bits > 32 ? 64 : 32), false};
                        call->register_writes.push_back(destination);
                        call->register_output_values.push_back(unknown_value(shape.value().type,
                            "DEX invocation result for immediately following move-result"));
                        call->result_type = shape.value().type;
                        statement.value() = Statement{Intrinsic{"dex_move_result_link", {}, IntrinsicMemoryEffect::none}};
                    }
                } else {
                    return Error{ErrorCode::malformed, "DEX move-result is not immediately adjacent to an invoke or filled-new-array in the same basic block"};
                }
            }
            ExpressionPtr divisor;
            bool division_or_remainder = false;
            bool wide = false;
            if ((op >= 0x90 && op <= 0x9a) || (op >= 0xb0 && op <= 0xba)) {
                const auto slot = static_cast<unsigned>(op >= 0xb0 ? op - 0xb0 : op - 0x90);
                division_or_remainder = slot == 3 || slot == 4;
                const auto index = op >= 0xb0 ? static_cast<std::uint16_t>(first >> 12)
                                               : static_cast<std::uint16_t>(unit(instruction, 1) >> 8);
                if (division_or_remainder) divisor = reg(vreg(index));
            } else if ((op >= 0x9b && op <= 0xa5) || (op >= 0xbb && op <= 0xc5)) {
                const auto slot = static_cast<unsigned>(op >= 0xbb ? op - 0xbb : op - 0x9b);
                division_or_remainder = slot == 3 || slot == 4;
                wide = true;
                const auto index = op >= 0xbb ? static_cast<std::uint16_t>(first >> 12)
                                               : static_cast<std::uint16_t>(unit(instruction, 1) >> 8);
                if (division_or_remainder) divisor = wide_reg(vreg(index));
            } else if (op >= 0xd0 && op <= 0xe2) {
                const bool literal16 = op <= 0xd7;
                const auto slot = static_cast<unsigned>(literal16 ? op - 0xd0 : op - 0xd8);
                division_or_remainder = slot == 3 || slot == 4;
                const auto packed = literal16 ? static_cast<std::uint16_t>(first >> 8) : unit(instruction, 1);
                const auto immediate = literal16
                    ? static_cast<std::int32_t>(std::bit_cast<std::int16_t>(unit(instruction, 1)))
                    : static_cast<std::int32_t>(std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(packed >> 8)));
                if (division_or_remainder) divisor = constant(static_cast<std::uint32_t>(immediate));
            }
            if (division_or_remainder)
                block.trap_edges.push_back({instruction.address, TrapEdgeKind::may_trap,
                    std::string("java.lang.ArithmeticException from ") + instruction.mnemonic_override,
                    predicate("eq", std::move(divisor), wide ? wide_constant(0) : constant(0))});
            if (auto *branch = std::get_if<Branch>(&statement.value())) {
                if (!instruction.direct_target || !block_entries.contains(
                        {instruction.direct_target->space.value, instruction.direct_target->offset}))
                    return Error{ErrorCode::unsupported, "DEX branch target is unresolved or outside the recovered method CFG"};
                for (const auto &edge : source.successors) {
                    if (!edge.target) continue;
                    if (edge.kind == BlockEdgeKind::conditional_true || edge.kind == BlockEdgeKind::jump)
                        branch->true_target = edge.target;
                    else if (edge.kind == BlockEdgeKind::conditional_false || edge.kind == BlockEdgeKind::fallthrough)
                        branch->false_target = edge.target;
                }
            }
            if (instruction.opcode != Opcode::dex_switch)
                block.instructions.push_back({{instruction.address, fact->id}, std::move(statement.value())});
            previous_instruction = &instruction;
        }
        if (!source.instructions.empty() &&
            source.instructions.back()->instruction.opcode == Opcode::dex_switch) {
            const auto &instruction = source.instructions.back()->instruction;
            if (!instruction.dex_switch || !instruction.dex_switch->validated)
                return Error{ErrorCode::unsupported, "DEX switch block has no validated case table"};
            LiftedBlock::SwitchDispatch dispatch;
            // The 11x DEX switch format carries an 8-bit register index, so
            // it is already within the common IR's register-key range.
            dispatch.selector = reg(vreg(unit(instruction, 0) >> 8));
            dispatch.complete = true;
            for (const auto &item : instruction.dex_switch->cases) {
                const bool has_case_edge = std::any_of(source.successors.begin(), source.successors.end(),
                    [&](const auto &edge) { return edge.kind == BlockEdgeKind::jump && edge.target == item.target; });
                if (!has_case_edge || !block_entries.contains({item.target.space.value, item.target.offset}))
                    return Error{ErrorCode::unsupported,
                                 "DEX switch case target is unresolved or outside the recovered method CFG"};
                dispatch.cases.push_back({static_cast<std::uint32_t>(item.value), item.target});
            }
            for (const auto &edge : source.successors)
                if (edge.kind == BlockEdgeKind::fallthrough && edge.target) {
                    dispatch.default_target = edge.target;
                    break;
                }
            if (!dispatch.default_target ||
                !block_entries.contains({dispatch.default_target->space.value, dispatch.default_target->offset}))
                return Error{ErrorCode::unsupported, "DEX switch default target is outside the recovered method CFG"};
            block.switch_dispatch = std::move(dispatch);
        }
        result.blocks.push_back(std::move(block));
    }
    if (result.blocks.empty()) return Error{ErrorCode::unsupported, "DEX function has no recovered blocks"};
    return result;
}
} // namespace hexlab::decompiler
