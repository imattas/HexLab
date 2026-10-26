#include "hexlab/decompiler/wasm_lifting.hpp"

#include <algorithm>
#include <array>
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

ValueType integer(unsigned bits, bool sign = false) { return {TypeKind::integer, static_cast<std::uint16_t>(bits), sign}; }
ValueType floating(unsigned bits) { return {TypeKind::floating, static_cast<std::uint16_t>(bits), false}; }
std::optional<ValueType> wasm_value_type(std::uint8_t code) {
    switch (code) {
    case 0x7f: return integer(32);
    case 0x7e: return integer(64);
    case 0x7d: return floating(32);
    case 0x7c: return floating(64);
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
std::optional<std::uint64_t> immediate(const Instruction &i, std::size_t n = 0) {
    if (n >= i.operands.size()) return {};
    if (const auto *v = std::get_if<ImmediateOperand>(&i.operands[n])) return v->value;
    return {};
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
struct MemoryOpInfo {
    bool store = false;
    ValueType stack_type;
    ValueType access_type;
    unsigned maximum_alignment_exponent = 0;
};
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
    struct Edge { std::size_t target; BlockEdgeKind kind; std::optional<std::size_t> label; };
    std::set<std::size_t> boundaries{0, code.size()};
    std::vector<std::vector<std::size_t>> active_labels(code.size());
    struct TableTarget { std::optional<std::uint64_t> value; std::size_t label; std::size_t target; };
    const auto table_targets = [&](std::size_t n) -> Result<std::vector<TableTarget>> {
        const auto &instruction = code[n]->instruction;
        const auto count = immediate(instruction, 0);
        if (!count || *count > 8 || instruction.operands.size() != *count + 2)
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
        auto to=block_for(target);if(!to)return false;successors[from].push_back({*to,kind,label});return true;
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
            if(op==0x3f||op==0x40)return unsupported("memory.size and memory.grow are not modeled");
            if(op==0x41||op==0x42||op==0x43||op==0x44){stack.push_back(op==0x41?integer(32):op==0x42?integer(64):op==0x43?floating(32):floating(64));}
            else if(auto info=numeric(op)){for(unsigned p=0;p<info->pops;++p){auto v=shape_pop(stack,info->input);if(!v)return v.error();}stack.push_back(info->output);}
            else if(auto cv=conversion(op)){auto v=shape_pop(stack,cv->input);if(!v)return v.error();stack.push_back(cv->output);}
            else if(op>=0xa7&&op<=0xbf)return unsupported("numeric conversion or reinterpret opcode is not modeled");
            else return unsupported("opcode/effect is not in the typed scalar subset: "+code[n]->instruction.mnemonic_override);
            if(stack.size()>max_stack)return Error{ErrorCode::resource_limit,"WebAssembly operand stack exceeds 128 values"};
        }
        exits[bi]=stack;
        for(const auto &edge:successors[bi]){
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
            auto &maps = incoming_slot_sources[edge.target];
            const auto [map_it, inserted] = maps.emplace(bi, source_slots);
            if (!inserted && map_it->second != source_slots)
                return unsupported("multiple edges from one block require different stack projections at a join");
            auto &inputs=predecessors[edge.target];if(std::find(inputs.begin(),inputs.end(),bi)==inputs.end())inputs.push_back(bi);
            if(!entries[edge.target]){entries[edge.target]=edge_shape;if(!queued[edge.target]){work.push_back(edge.target);queued[edge.target]=true;}}
            else if(*entries[edge.target]!=edge_shape)return unsupported("operand stack shapes disagree at a control-flow join");
        }
    }

    auto function_result_types = signature_results();
    if (!function_result_types) return function_result_types.error();
    LiftedFunction out{function.id,function.entry,{},{}};
    std::vector<std::vector<std::uint32_t>> output_versions(starts.size()),phi_versions(starts.size());
    std::array<std::uint32_t,256> versions{};
    for(std::size_t bi=0;bi<starts.size();++bi)if(entries[bi]){
        if(exits[bi]&&!successors[bi].empty()){output_versions[bi].resize(exits[bi]->size());for(std::size_t slot=0;slot<exits[bi]->size();++slot)output_versions[bi][slot]=++versions[slot];}
        if(predecessors[bi].size()>1){phi_versions[bi].resize(entries[bi]->size());for(std::size_t slot=0;slot<entries[bi]->size();++slot)phi_versions[bi][slot]=++versions[slot];}
    }
    for(std::size_t bi=0;bi<starts.size();++bi)if(entries[bi]){
        const auto begin=starts[bi],finish=bi+1<starts.size()?starts[bi+1]:code.size(),last=finish-1;
        const BlockId id{static_cast<std::uint64_t>(bi+1)};
        LiftedBlock lifted{id,code[begin]->instruction.address,{},{}};
        for(const auto &edge:successors[bi]){const auto target_addr=code[starts[edge.target]]->instruction.address;lifted.successors.push_back({code[last]->instruction.address,target_addr,BlockId{static_cast<std::uint64_t>(edge.target+1)},edge.kind});}
        for(std::size_t n=begin;n<finish;++n){
            const auto op=std::to_integer<std::uint8_t>(code[n]->instruction.bytes[0]);
            if(op==0x00)
                lifted.trap_edges.push_back({code[n]->instruction.address,TrapEdgeKind::unconditional,"unreachable"});
            else if(op==0x11) lifted.trap_edges.push_back({code[n]->instruction.address,TrapEdgeKind::may_trap,"call_indirect table bounds or type mismatch"});
            if(op==0x00)break;
        }
        for(std::size_t slot=0;slot<phi_versions[bi].size();++slot){const RegisterOperand reg{RegisterBank::wasm_stack,static_cast<std::uint8_t>(slot),entries[bi]->at(slot).bits,false};LiftedBlock::Phi phi{reg,phi_versions[bi][slot],{}};for(const auto pred:predecessors[bi]){const auto projection=incoming_slot_sources[bi].find(pred);if(projection==incoming_slot_sources[bi].end()||slot>=projection->second.size())return Error{ErrorCode::malformed,"WebAssembly predecessor stack projection is unavailable"};const auto source_slot=projection->second[slot];if(source_slot>=output_versions[pred].size())return Error{ErrorCode::malformed,"WebAssembly predecessor has no stack value for join"};phi.inputs.push_back({BlockId{static_cast<std::uint64_t>(pred+1)},output_versions[pred][source_slot]});}lifted.phis.push_back(std::move(phi));}
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
            if(op==0x41||op==0x42||op==0x43||op==0x44){auto v=immediate(i);if(!v)return unsupported("constant immediate unavailable");stack.push_back(constant(*v,op==0x41?integer(32):op==0x42?integer(64):op==0x43?floating(32):floating(64)));continue;}
            if(op==0x00){emit(n,Intrinsic{"wasm_unreachable",{},IntrinsicMemoryEffect::none});break;}
            if(op==0x01)continue;
            if(op==2||op==3){continue;}
            if(op==4){auto cond=pop(integer(32));if(!cond)return cond.error();const auto li=*opener_label[n];const auto yes=code[n+1]->instruction.address;const auto target=labels[li].else_index<code.size()?labels[li].else_index+1:labels[li].end+1;emit(n,Branch{"wasm_if",yes,code[target]->instruction.address,cond.value()});continue;}
            if(op==5){const auto li=active_labels[n].back();auto values=take_results(labels[li].result_types);if(!values)return values.error();if(!label_heights[li]||stack.size()<*label_heights[li])return unsupported("if then-arm stack height is unavailable");stack.resize(*label_heights[li]);stack.insert(stack.end(),values.value().begin(),values.value().end());const auto target=labels[li].end+1;emit(n,Branch{"true",code[target]->instruction.address,{}});continue;}
            if(op==0x0b){if(end_label[n]){const auto li=*end_label[n];auto values=take_results(labels[li].result_types);if(!values)return values.error();if(!label_heights[li]||stack.size()<*label_heights[li])return unsupported("block stack height is unavailable");stack.resize(*label_heights[li]);stack.insert(stack.end(),values.value().begin(),values.value().end());}else if(n==function_end){auto result=emit_return(n,function_result_types.value());if(!result)return result.error();}continue;}
            if(op==0x0f){auto result=emit_return(n,function_result_types.value());if(!result)return result.error();continue;}
            if(op==0x0c||op==0x0d){auto depth=immediate(i);if(!depth)return unsupported("branch depth unavailable");const auto li=active_labels[n][active_labels[n].size()-1-static_cast<std::size_t>(*depth)];const auto target=li==function_label?function_end:labels[li].kind==3?labels[li].opener+1:labels[li].end+1;if(op==0x0c)emit(n,Branch{"true",code[target]->instruction.address,{}});else{auto cond=pop(integer(32));if(!cond)return cond.error();emit(n,Branch{"br_if",code[target]->instruction.address,n+1<code.size()?std::optional<Address>{code[n+1]->instruction.address}:std::nullopt,cond.value()});}continue;}
            if(op==0x0e){auto selector=pop(integer(32));if(!selector)return selector.error();auto targets=table_targets(n);if(!targets)return targets.error();LiftedBlock::SwitchDispatch dispatch;dispatch.selector=selector.value();for(const auto &target:targets.value()){const auto target_block=block_for(target.target);if(!target_block)return unsupported("br_table target is not a basic block");const auto address=code[starts[*target_block]]->instruction.address;if(target.value)dispatch.cases.push_back({*target.value,address});else dispatch.default_target=address;}lifted.switch_dispatch=std::move(dispatch);continue;}
            if(op==0x1a){auto v=pop({});if(!v)return v.error();continue;}
            if(op==0x1b){auto cond=pop(integer(32));if(!cond)return cond.error();auto when_true=pop({});if(!when_true)return when_true.error();auto when_false=pop(when_true.value()->type);if(!when_false)return when_false.error();auto alternatives=binary("pair",when_true.value(),when_false.value(),when_true.value()->type);stack.push_back(binary("select_if",cond.value(),alternatives,when_true.value()->type));continue;}
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
            if(op==0x3f||op==0x40)return unsupported("memory.size and memory.grow are not modeled");
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
    return out;
}
} // namespace hexlab::decompiler
