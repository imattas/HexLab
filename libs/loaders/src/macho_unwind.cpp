#include "hexlab/loaders/macho_unwind.hpp"
#include "hexlab/core/result.hpp"
#include <algorithm>
#include <bit>
#include <vector>

namespace hexlab {
namespace {
constexpr std::uint32_t x86_64_cpu = 0x01000007u;
constexpr std::uint32_t arm64_cpu = 0x0100000cu;
constexpr std::uint32_t mode_mask = 0x0f000000u;

Error failure(ErrorCode code, const char *message) { return {code, message}; }

std::optional<std::uint64_t> reg(const MachOUnwindContext &context, MachOUnwindRegister id) {
    const auto it = context.find(id);
    if (it == context.end()) return std::nullopt;
    return it->second;
}

bool add(std::uint64_t a, std::uint64_t b, std::uint64_t &out) {
    if (b > UINT64_MAX - a) return false;
    out = a + b;
    return true;
}

bool sub(std::uint64_t a, std::uint64_t b, std::uint64_t &out) {
    if (b > a) return false;
    out = a - b;
    return true;
}

Result<std::uint64_t> word(const MachOUnwindMemoryReader &read, std::uint64_t at) {
    if (!read) return failure(ErrorCode::invalid_argument, "Mach-O unwind memory reader is empty");
    const auto value = read(at, 8);
    if (!value) return failure(ErrorCode::out_of_bounds, "Mach-O unwind stack read failed");
    return *value;
}

Result<std::uint64_t> cfi_uleb(std::span<const std::byte> bytes, std::size_t &cursor) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 10; ++i) {
        if (cursor >= bytes.size()) return failure(ErrorCode::malformed, "Truncated Mach-O CFI ULEB");
        const auto byte = std::to_integer<unsigned>(bytes[cursor++]);
        if (i == 9 && ((byte & 0x7e) || (byte & 0x80))) return failure(ErrorCode::overflow, "Mach-O CFI ULEB overflows");
        value |= std::uint64_t(byte & 0x7f) << (7 * i);
        if (!(byte & 0x80)) return value;
    }
    return failure(ErrorCode::malformed, "Mach-O CFI ULEB exceeds ten bytes");
}

Result<std::int64_t> cfi_sleb(std::span<const std::byte> bytes, std::size_t &cursor) {
    std::uint64_t value = 0;
    unsigned shift = 0, byte = 0;
    for (unsigned i = 0; i < 10; ++i) {
        if (cursor >= bytes.size()) return failure(ErrorCode::malformed, "Truncated Mach-O CFI SLEB");
        byte = std::to_integer<unsigned>(bytes[cursor++]);
        if (i == 9 && byte != 0 && byte != 0x7f)
            return failure(ErrorCode::overflow, "Mach-O CFI SLEB overflows");
        value |= std::uint64_t(byte & 0x7f) << shift;
        shift += 7;
        if (!(byte & 0x80)) {
            if (shift < 64 && (byte & 0x40)) value |= (~UINT64_C(0)) << shift;
            return static_cast<std::int64_t>(value);
        }
    }
    return failure(ErrorCode::malformed, "Mach-O CFI SLEB exceeds ten bytes");
}

struct CfiRule {
    enum class Kind { offset, value_offset, expression, value_expression, same, undefined, reg } kind = Kind::same;
    std::int64_t offset = 0;
    std::uint64_t reg = 0;
    std::vector<std::byte> expression;
};
struct CfiState {
    std::optional<std::uint64_t> cfa_register;
    std::int64_t cfa_offset = 0;
    std::optional<std::vector<std::byte>> cfa_expression;
    std::map<std::uint64_t, CfiRule> rules;
    bool return_address_signed = false;
    std::optional<std::uint64_t> gnu_args_size;
};

std::optional<MachOUnwindRegister> cfi_register(std::uint32_t cpu, std::uint64_t number) {
    if (cpu == x86_64_cpu) {
        switch (number) {
        case 3: return MachOUnwindRegister::x86_64_rbx;
        case 6: return MachOUnwindRegister::x86_64_rbp;
        case 7: return MachOUnwindRegister::x86_64_rsp;
        case 12: return MachOUnwindRegister::x86_64_r12;
        case 13: return MachOUnwindRegister::x86_64_r13;
        case 14: return MachOUnwindRegister::x86_64_r14;
        case 15: return MachOUnwindRegister::x86_64_r15;
        case 16: return MachOUnwindRegister::x86_64_rip;
        default: return std::nullopt;
        }
    }
    if (cpu == arm64_cpu) {
        if (number >= 19 && number <= 30)
            return static_cast<MachOUnwindRegister>(static_cast<unsigned>(MachOUnwindRegister::arm64_x19) +
                                                     static_cast<unsigned>(number - 19));
        if (number >= 72 && number <= 79)
            return static_cast<MachOUnwindRegister>(static_cast<unsigned>(MachOUnwindRegister::arm64_d8) +
                                                     static_cast<unsigned>(number - 72));
        if (number == 31) return MachOUnwindRegister::arm64_sp;
    }
    return std::nullopt;
}

Result<std::int64_t> cfi_scale_signed(std::int64_t factor, std::int64_t alignment) {
    if (factor == 0 || alignment == 0) return std::int64_t{0};
    const auto factor_magnitude = factor < 0 ? std::uint64_t(-(factor + 1)) + 1 : std::uint64_t(factor);
    const auto alignment_magnitude = alignment < 0 ? std::uint64_t(-(alignment + 1)) + 1 : std::uint64_t(alignment);
    if (factor_magnitude > std::uint64_t(INT64_MAX) / alignment_magnitude)
        return failure(ErrorCode::overflow, "Mach-O CFI scaled offset overflows");
    const auto product = static_cast<std::int64_t>(factor_magnitude * alignment_magnitude);
    return ((factor < 0) != (alignment < 0)) ? -product : product;
}

Result<std::int64_t> cfi_scale(std::uint64_t factor, std::int64_t alignment) {
    if (factor > std::uint64_t(INT64_MAX)) return failure(ErrorCode::overflow, "Mach-O CFI offset factor overflows");
    return cfi_scale_signed(static_cast<std::int64_t>(factor), alignment);
}

Result<bool> run_cfi(std::span<const std::byte> instructions, std::uint32_t cpu, std::uint64_t code_alignment,
                     std::int64_t data_alignment, std::uint64_t target, std::uint64_t &location,
                     CfiState &state, const CfiState &initial,
                     std::optional<std::uint64_t> fde_begin = std::nullopt,
                     std::uint64_t fde_size = 0) {
    std::size_t cursor = 0;
    auto read_u = [&]() { return cfi_uleb(instructions, cursor); };
    auto read_s = [&]() { return cfi_sleb(instructions, cursor); };
    auto set_offset = [&](std::uint64_t reg, std::uint64_t factor) -> Result<bool> {
        auto scaled = cfi_scale(factor, data_alignment);
        if (!scaled) return scaled.error();
        state.rules[reg] = {CfiRule::Kind::offset, scaled.value(), 0};
        return true;
    };
    std::vector<CfiState> saved_states;
    constexpr std::size_t max_state_depth = 1024;
    while (cursor < instructions.size()) {
        const auto op = std::to_integer<unsigned>(instructions[cursor++]);
        const auto primary = op & 0xc0;
        if (primary == 0x40 || op == 2 || op == 3 || op == 4) {
            std::uint64_t delta = op & 0x3f;
            if (op == 2) { if (cursor >= instructions.size()) return failure(ErrorCode::malformed, "Truncated CFI advance_loc1"); delta = std::to_integer<unsigned>(instructions[cursor++]); }
            else if (op == 3 || op == 4) {
                const auto width = op == 3 ? 2u : 4u;
                if (width > instructions.size() - cursor) return failure(ErrorCode::malformed, "Truncated CFI advance_loc");
                delta = 0; for (unsigned i = 0; i < width; ++i) delta |= std::uint64_t(std::to_integer<unsigned>(instructions[cursor++])) << (8 * i);
            }
            if (delta && code_alignment > UINT64_MAX / delta) return failure(ErrorCode::overflow, "Mach-O CFI location advance overflows");
            const auto advance = delta * code_alignment;
            if (advance > UINT64_MAX - location) return failure(ErrorCode::overflow, "Mach-O CFI location overflows");
            if (location + advance > target) break;
            location += advance;
            continue;
        }
        if (primary == 0x80) {
            auto factor = read_u(); if (!factor) return factor.error();
            auto result = set_offset(op & 0x3f, factor.value()); if (!result) return result.error();
            continue;
        }
        if (primary == 0xc0) {
            const auto reg = op & 0x3f;
            if (const auto it = initial.rules.find(reg); it != initial.rules.end()) state.rules[reg] = it->second;
            else state.rules.erase(reg);
            continue;
        }
        switch (op) {
        case 0: break; // nop
        case 1: { // DW_CFA_set_loc: absolute address-sized location in an FDE program
            if (!fde_begin)
                return failure(ErrorCode::unsupported, "Mach-O DW_CFA_set_loc has no FDE address context");
            if (instructions.size() - cursor < 8)
                return failure(ErrorCode::malformed, "Truncated Mach-O DW_CFA_set_loc address");
            std::uint64_t absolute = 0;
            for (unsigned i = 0; i < 8; ++i)
                absolute |= std::uint64_t(std::to_integer<unsigned>(instructions[cursor++])) << (8 * i);
            if (absolute < *fde_begin || absolute - *fde_begin > fde_size)
                return failure(ErrorCode::malformed, "Mach-O DW_CFA_set_loc address is outside its FDE interval");
            const auto next_location = absolute - *fde_begin;
            if (next_location < location)
                return failure(ErrorCode::malformed, "Mach-O DW_CFA_set_loc moves the location backwards");
            if (next_location > target) return true;
            location = next_location;
            break;
        }
        case 5: case 6: case 7: case 8: {
            auto reg = read_u(); if (!reg) return reg.error();
            if (op == 5) { auto factor = read_u(); if (!factor) return factor.error(); auto result=set_offset(reg.value(),factor.value()); if(!result)return result.error(); }
            else if (op == 6) { if (const auto it=initial.rules.find(reg.value()); it!=initial.rules.end()) state.rules[reg.value()]=it->second; else state.rules.erase(reg.value()); }
            else state.rules[reg.value()] = {op == 7 ? CfiRule::Kind::undefined : CfiRule::Kind::same, 0, 0};
            break;
        }
        case 9: {
            auto reg = read_u(); if (!reg) return reg.error(); auto source = read_u(); if (!source) return source.error();
            state.rules[reg.value()] = {CfiRule::Kind::reg, 0, source.value()}; break;
        }
        case 16: case 22: {
            auto reg = read_u(); if (!reg) return reg.error();
            auto length = read_u(); if (!length) return length.error();
            if (length.value() > 4096)
                return failure(ErrorCode::resource_limit, "Mach-O CFI expression block exceeds size limit");
            if (length.value() > instructions.size() - cursor)
                return failure(ErrorCode::malformed, "Truncated Mach-O CFI expression block");
            const auto size = static_cast<std::size_t>(length.value());
            CfiRule rule;
            rule.kind = op == 16 ? CfiRule::Kind::expression : CfiRule::Kind::value_expression;
            rule.expression.assign(instructions.begin() + static_cast<std::ptrdiff_t>(cursor),
                                   instructions.begin() + static_cast<std::ptrdiff_t>(cursor + size));
            cursor += size;
            state.rules[reg.value()] = std::move(rule);
            break;
        }
        case 12: {
            auto reg=read_u(); if(!reg)return reg.error(); auto offset=read_u(); if(!offset)return offset.error();
            if(offset.value()>std::uint64_t(INT64_MAX))return failure(ErrorCode::overflow,"Mach-O CFI CFA offset overflows");
            state.cfa_register=reg.value(); state.cfa_offset=static_cast<std::int64_t>(offset.value()); state.cfa_expression.reset(); break;
        }
        case 13: { auto reg=read_u(); if(!reg)return reg.error(); if (!state.cfa_register || state.cfa_expression) return failure(ErrorCode::malformed,"Mach-O CFI def_cfa_register has no register-based CFA rule"); state.cfa_register=reg.value(); break; }
        case 14: { auto offset=read_u(); if(!offset)return offset.error(); if(offset.value()>std::uint64_t(INT64_MAX))return failure(ErrorCode::overflow,"Mach-O CFI CFA offset overflows"); if (!state.cfa_register || state.cfa_expression) return failure(ErrorCode::malformed,"Mach-O CFI def_cfa_offset has no register-based CFA rule"); state.cfa_offset=static_cast<std::int64_t>(offset.value()); break; }
        case 15: {
            auto length=read_u(); if(!length)return length.error();
            if(length.value()>4096)return failure(ErrorCode::resource_limit,"Mach-O CFI CFA expression block exceeds size limit");
            if(length.value()>instructions.size()-cursor)return failure(ErrorCode::malformed,"Truncated Mach-O CFI CFA expression block");
            const auto size=static_cast<std::size_t>(length.value());
            state.cfa_expression.emplace(instructions.begin()+static_cast<std::ptrdiff_t>(cursor),
                                         instructions.begin()+static_cast<std::ptrdiff_t>(cursor+size));
            state.cfa_register.reset(); state.cfa_offset=0; cursor+=size; break;
        }
        case 17: { auto reg=read_u(); if(!reg)return reg.error(); auto factor=read_s(); if(!factor)return factor.error(); auto scaled=cfi_scale_signed(factor.value(),data_alignment); if(!scaled)return scaled.error(); state.rules[reg.value()]={CfiRule::Kind::offset,scaled.value(),0}; break; }
        case 18: { auto reg=read_u(); if(!reg)return reg.error(); auto offset=read_s(); if(!offset)return offset.error(); auto scaled=cfi_scale_signed(offset.value(),data_alignment); if(!scaled)return scaled.error(); state.cfa_register=reg.value(); state.cfa_offset=scaled.value(); state.cfa_expression.reset(); break; }
        case 19: { auto offset=read_s(); if(!offset)return offset.error(); auto scaled=cfi_scale_signed(offset.value(),data_alignment); if(!scaled)return scaled.error(); if (!state.cfa_register || state.cfa_expression) return failure(ErrorCode::malformed,"Mach-O CFI def_cfa_offset_sf has no register-based CFA rule"); state.cfa_offset=scaled.value(); break; }
        case 20: { auto reg=read_u(); if(!reg)return reg.error(); auto factor=read_u(); if(!factor)return factor.error(); auto scaled=cfi_scale(factor.value(),data_alignment); if(!scaled)return scaled.error(); state.rules[reg.value()]={CfiRule::Kind::value_offset,scaled.value(),0}; break; }
        case 21: { auto reg=read_u(); if(!reg)return reg.error(); auto factor=read_s(); if(!factor)return factor.error(); auto scaled=cfi_scale_signed(factor.value(),data_alignment); if(!scaled)return scaled.error(); state.rules[reg.value()]={CfiRule::Kind::value_offset,scaled.value(),0}; break; }
        // GCC's DW_CFA_GNU_negative_offset_extended encodes an unsigned
        // factor whose effective offset is negated before data_alignment.
        case 0x2f: {
            auto reg = read_u(); if (!reg) return reg.error();
            auto factor = read_u(); if (!factor) return factor.error();
            if (factor.value() > static_cast<std::uint64_t>(INT64_MAX))
                return failure(ErrorCode::overflow, "Mach-O GNU CFI negative offset factor overflows");
            const auto negative_factor = -static_cast<std::int64_t>(factor.value());
            auto scaled = cfi_scale_signed(negative_factor, data_alignment);
            if (!scaled) return scaled.error();
            state.rules[reg.value()] = {CfiRule::Kind::offset, scaled.value(), 0};
            break;
        }
        case 0x2d:
            // On AArch64 this is DW_CFA_AARCH64_negate_ra_state. It is
            // architecture-overloaded with GNU window-save on SPARC, which
            // this Mach-O evaluator does not support.
            if (cpu != arm64_cpu)
                return failure(ErrorCode::unsupported, "Mach-O GNU window-save CFI is unsupported");
            state.return_address_signed = !state.return_address_signed;
            break;
        case 0x2e: {
            if (cpu != x86_64_cpu)
                return failure(ErrorCode::unsupported, "Mach-O GNU args-size CFI is supported only for x86_64");
            auto size = read_u(); if (!size) return size.error();
            state.gnu_args_size = size.value();
            break;
        }
        case 10:
            if (saved_states.size() >= max_state_depth)
                return failure(ErrorCode::resource_limit, "Mach-O CFI remember_state nesting exceeds limit");
            saved_states.push_back(state);
            break;
        case 11:
            if (saved_states.empty())
                return failure(ErrorCode::malformed, "Mach-O CFI restore_state has no matching remember_state");
            state = std::move(saved_states.back());
            saved_states.pop_back();
            break;
        default: return failure(ErrorCode::unsupported, "Mach-O CFI opcode is outside the supported subset");
        }
    }
    return true;
}

bool cfi_add(std::uint64_t base, std::int64_t offset, std::uint64_t &result) {
    if (offset >= 0) return add(base, static_cast<std::uint64_t>(offset), result);
    return sub(base, static_cast<std::uint64_t>(-(offset + 1)) + 1, result);
}

struct CfiExpressionValue {
    std::uint64_t value = 0;
    bool is_value = false;
    // DW_OP_reg* produces a register location, not the register's current value.
    std::optional<std::uint64_t> register_location;
};

Result<CfiExpressionValue> evaluate_cfi_expression(std::span<const std::byte> expression,
                                               std::uint32_t cpu,
                                               const MachOUnwindContext &context,
                                               std::uint64_t cfa,
                                               const MachOUnwindMemoryReader &read,
                                               bool allow_call_frame_cfa = true) {
    std::vector<CfiExpressionValue> stack;
    stack.reserve(8);
    std::size_t cursor = 0;
    std::size_t operations = 0;
    auto push = [&](std::uint64_t value, bool is_value = false,
                    std::optional<std::uint64_t> register_location = std::nullopt) -> Result<bool> {
        if (stack.size() >= 16) return failure(ErrorCode::resource_limit, "Mach-O CFI expression stack exceeds limit");
        stack.push_back({value, is_value, register_location});
        return true;
    };
    auto pop = [&]() -> Result<std::uint64_t> {
        if (stack.empty()) return failure(ErrorCode::malformed, "Mach-O CFI expression stack underflow");
        const auto value = stack.back();
        stack.pop_back();
        if (value.register_location)
            return failure(ErrorCode::unsupported, "Mach-O CFI register-location result cannot be used as an arithmetic operand");
        return value.value;
    };
    auto binary = [&](auto operation) -> Result<bool> {
        auto rhs = pop(); if (!rhs) return rhs.error();
        auto lhs = pop(); if (!lhs) return lhs.error();
        return push(operation(lhs.value(), rhs.value()));
    };
    auto fixed_constant = [&](unsigned width, bool is_signed) -> Result<std::uint64_t> {
        if (width > expression.size() - cursor)
            return failure(ErrorCode::malformed, "Truncated Mach-O fixed-width CFI expression constant");
        std::uint64_t value = 0;
        for (unsigned i = 0; i < width; ++i)
            value |= std::uint64_t(std::to_integer<unsigned>(expression[cursor++])) << (8 * i);
        if (is_signed && width < 8 && (value & (std::uint64_t{1} << (width * 8 - 1)))) {
            const auto mask = (std::uint64_t{1} << (width * 8)) - 1;
            value |= ~mask;
        }
        return value;
    };
    while (cursor < expression.size()) {
        if (++operations > 64) return failure(ErrorCode::resource_limit, "Mach-O CFI expression exceeds operation limit");
        const auto op = std::to_integer<unsigned>(expression[cursor++]);
        if (op >= 0x30 && op <= 0x4f) { // DW_OP_lit0..DW_OP_lit31
            auto result = push(op - 0x30); if (!result) return result.error();
            continue;
        }
        if (op >= 0x50 && op <= 0x6f) { // DW_OP_reg0..DW_OP_reg31
            auto result = push(0, false, op - 0x50); if (!result) return result.error();
            continue;
        }
        if (op >= 0x70 && op <= 0x8f) {
            const auto number = op - 0x70;
            auto offset = cfi_sleb(expression, cursor); if (!offset) return offset.error();
            const auto id = cfi_register(cpu, number);
            if (!id) return failure(ErrorCode::unsupported, "Mach-O CFI expression names an unsupported base register");
            const auto base = reg(context, *id);
            if (!base) return failure(ErrorCode::malformed, "Mach-O CFI expression base register is unavailable");
            std::uint64_t value = 0;
            if (!cfi_add(*base, offset.value(), value)) return failure(ErrorCode::overflow, "Mach-O CFI expression address overflows");
            auto result = push(value); if (!result) return result.error();
            continue;
        }
        switch (op) {
        case 0x12: { // DW_OP_dup
            if (stack.empty()) return failure(ErrorCode::malformed, "Mach-O CFI expression stack underflow");
            auto result = push(stack.back().value, stack.back().is_value,
                               stack.back().register_location); if (!result) return result.error();
            break;
        }
        case 0x13: { // DW_OP_drop
            auto value = pop(); if (!value) return value.error();
            break;
        }
        case 0x14: // DW_OP_over
        case 0x15: { // DW_OP_pick
            std::size_t index = 1;
            if (op == 0x15) {
                if (cursor >= expression.size()) return failure(ErrorCode::malformed, "Truncated Mach-O DW_OP_pick index");
                index = std::to_integer<unsigned>(expression[cursor++]);
            }
            if (index >= stack.size()) return failure(ErrorCode::malformed, "Mach-O DW_OP_pick index exceeds expression stack");
            auto result = push(stack[stack.size() - 1 - index].value,
                               stack[stack.size() - 1 - index].is_value,
                               stack[stack.size() - 1 - index].register_location); if (!result) return result.error();
            break;
        }
        case 0x16: { // DW_OP_swap
            if (stack.size() < 2) return failure(ErrorCode::malformed, "Mach-O CFI expression stack underflow");
            std::iter_swap(stack.end() - 1, stack.end() - 2);
            break;
        }
        case 0x17: { // DW_OP_rot: top becomes third, second becomes top
            if (stack.size() < 3) return failure(ErrorCode::malformed, "Mach-O CFI expression stack underflow");
            const auto top = stack.back();
            stack.back() = stack[stack.size() - 2];
            stack[stack.size() - 2] = stack[stack.size() - 3];
            stack[stack.size() - 3] = top;
            break;
        }
        case 0x19: { // DW_OP_abs
            if (stack.empty()) return failure(ErrorCode::malformed, "Mach-O CFI expression stack underflow");
            if (stack.back().register_location) return failure(ErrorCode::unsupported, "Mach-O CFI register location cannot be used by DW_OP_abs");
            const auto signed_value = std::bit_cast<std::int64_t>(stack.back().value);
            if (signed_value == INT64_MIN) return failure(ErrorCode::overflow, "Mach-O DW_OP_abs overflows");
            if (signed_value < 0) stack.back().value = static_cast<std::uint64_t>(-signed_value);
            break;
        }
        case 0x1f: { // DW_OP_neg
            if (stack.empty()) return failure(ErrorCode::malformed, "Mach-O CFI expression stack underflow");
            if (stack.back().register_location) return failure(ErrorCode::unsupported, "Mach-O CFI register location cannot be used by DW_OP_neg");
            if (stack.back().value == (std::uint64_t{1} << 63))
                return failure(ErrorCode::overflow, "Mach-O DW_OP_neg result is not representable");
            stack.back().value = std::uint64_t{0} - stack.back().value;
            break;
        }
        case 0x20: { // DW_OP_not
            if (stack.empty()) return failure(ErrorCode::malformed, "Mach-O CFI expression stack underflow");
            if (stack.back().register_location) return failure(ErrorCode::unsupported, "Mach-O CFI register location cannot be used by DW_OP_not");
            stack.back().value = ~stack.back().value;
            break;
        }
        case 0x10: { // DW_OP_constu
            auto value=cfi_uleb(expression,cursor); if(!value)return value.error();
            auto result=push(value.value()); if(!result)return result.error(); break;
        }
        case 0x11: { // DW_OP_consts
            auto value=cfi_sleb(expression,cursor); if(!value)return value.error();
            auto result=push(static_cast<std::uint64_t>(value.value())); if(!result)return result.error(); break;
        }
        case 0x08: case 0x09: // DW_OP_const1u / DW_OP_const1s
        case 0x0a: case 0x0b: // DW_OP_const2u / DW_OP_const2s
        case 0x0c: case 0x0d: // DW_OP_const4u / DW_OP_const4s
        case 0x0e: case 0x0f: { // DW_OP_const8u / DW_OP_const8s
            const auto width = 1u << ((op - 0x08) / 2);
            auto value = fixed_constant(width, (op & 1) != 0); if (!value) return value.error();
            auto result = push(value.value()); if (!result) return result.error();
            break;
        }
        case 0x06: { // DW_OP_deref
            auto address = pop(); if (!address) return address.error();
            auto value = word(read, address.value()); if (!value) return value.error();
            auto result = push(value.value()); if (!result) return result.error();
            break;
        }
        case 0x94: { // DW_OP_deref_size
            if (cursor >= expression.size()) return failure(ErrorCode::malformed, "Truncated Mach-O DW_OP_deref_size width");
            const auto width = std::to_integer<unsigned>(expression[cursor++]);
            if (width == 0 || width > 8) return failure(ErrorCode::unsupported, "Mach-O DW_OP_deref_size exceeds the 64-bit target address size");
            auto address = pop(); if (!address) return address.error();
            if (!read) return failure(ErrorCode::invalid_argument, "Mach-O CFI expression memory reader is empty");
            const auto loaded = read(address.value(), static_cast<std::uint8_t>(width));
            if (!loaded) return failure(ErrorCode::out_of_bounds, "Mach-O CFI expression sized read failed");
            const auto mask = width == 8 ? UINT64_MAX : (std::uint64_t{1} << (width * 8)) - 1;
            auto result = push(*loaded & mask); if (!result) return result.error();
            break;
        }
        case 0x23: { // DW_OP_plus_uconst
            auto amount = cfi_uleb(expression, cursor); if (!amount) return amount.error();
            if (stack.empty()) return failure(ErrorCode::malformed, "Mach-O CFI expression stack underflow");
            if (stack.back().register_location) return failure(ErrorCode::unsupported, "Mach-O CFI register location cannot be used by DW_OP_plus_uconst");
            stack.back().value += amount.value(); // DWARF addressing arithmetic wraps modulo 2^64.
            break;
        }
        case 0x9e: { // DW_OP_implicit_value
            auto length = cfi_uleb(expression, cursor);
            if (!length) return length.error();
            if (length.value() > 8)
                return failure(ErrorCode::unsupported, "Mach-O CFI implicit value exceeds the 64-bit register width");
            if (length.value() > expression.size() - cursor)
                return failure(ErrorCode::malformed, "Truncated Mach-O DW_OP_implicit_value block");
            std::uint64_t value = 0;
            for (std::uint64_t i = 0; i < length.value(); ++i)
                value |= std::uint64_t(std::to_integer<unsigned>(expression[cursor++])) << (8 * i);
            auto result = push(value, true);
            if (!result) return result.error();
            break;
        }
        case 0x9f: { // DW_OP_stack_value
            if (stack.empty()) return failure(ErrorCode::malformed, "Mach-O CFI expression stack underflow");
            stack.back().is_value = true;
            break;
        }
        case 0x1a: // DW_OP_and
            { auto result = binary([](auto a, auto b) { return a & b; }); if (!result) return result.error(); break; }
        case 0x1b: { // DW_OP_div (signed)
            auto rhs = pop(); if (!rhs) return rhs.error(); auto lhs = pop(); if (!lhs) return lhs.error();
            const auto divisor = std::bit_cast<std::int64_t>(rhs.value());
            const auto dividend = std::bit_cast<std::int64_t>(lhs.value());
            if (!divisor) return failure(ErrorCode::malformed, "Mach-O DW_OP_div divides by zero");
            if (dividend == INT64_MIN && divisor == -1) return failure(ErrorCode::overflow, "Mach-O DW_OP_div overflows");
            auto result = push(std::bit_cast<std::uint64_t>(dividend / divisor)); if (!result) return result.error(); break;
        }
        case 0x1c: // DW_OP_minus (unsigned target-width wrapping)
            { auto result = binary([](auto a, auto b) { return a - b; }); if (!result) return result.error(); break; }
        case 0x1d: { // DW_OP_mod (signed)
            auto rhs = pop(); if (!rhs) return rhs.error(); auto lhs = pop(); if (!lhs) return lhs.error();
            const auto divisor = std::bit_cast<std::int64_t>(rhs.value());
            const auto dividend = std::bit_cast<std::int64_t>(lhs.value());
            if (!divisor) return failure(ErrorCode::malformed, "Mach-O DW_OP_mod divides by zero");
            if (dividend == INT64_MIN && divisor == -1) return failure(ErrorCode::overflow, "Mach-O DW_OP_mod overflows");
            auto result = push(std::bit_cast<std::uint64_t>(dividend % divisor)); if (!result) return result.error(); break;
        }
        case 0x1e: // DW_OP_mul (unsigned target-width wrapping)
            { auto result = binary([](auto a, auto b) { return a * b; }); if (!result) return result.error(); break; }
        case 0x21: // DW_OP_or
            { auto result = binary([](auto a, auto b) { return a | b; }); if (!result) return result.error(); break; }
        case 0x22: // DW_OP_plus (unsigned target-width wrapping)
            { auto result = binary([](auto a, auto b) { return a + b; }); if (!result) return result.error(); break; }
        case 0x24: case 0x25: case 0x26: { // DW_OP_shl / shr / shra
            auto rhs = pop(); if (!rhs) return rhs.error(); auto lhs = pop(); if (!lhs) return lhs.error();
            if (rhs.value() >= 64) return failure(ErrorCode::malformed, "Mach-O CFI expression shift count is outside 0..63");
            const auto shift = static_cast<unsigned>(rhs.value());
            std::uint64_t value = 0;
            if (op == 0x24) value = lhs.value() << shift;
            else if (op == 0x25) value = lhs.value() >> shift;
            else if (shift == 0) value = lhs.value();
            else if (op == 0x25) value = lhs.value() >> shift;
            else {
                const bool negative = (lhs.value() & (std::uint64_t{1} << 63)) != 0;
                const auto magnitude = negative ? (std::uint64_t{0} - lhs.value()) : lhs.value();
                const auto shifted = magnitude >> shift;
                value = negative ? (std::uint64_t{0} - shifted) : shifted;
            }
            auto result = push(value); if (!result) return result.error(); break;
        }
        case 0x27: // DW_OP_xor
            { auto result = binary([](auto a, auto b) { return a ^ b; }); if (!result) return result.error(); break; }
        case 0x29: case 0x2a: case 0x2b: case 0x2c: case 0x2d: case 0x2e: { // comparisons
            auto rhs = pop(); if (!rhs) return rhs.error(); auto lhs = pop(); if (!lhs) return lhs.error();
            const auto signed_lhs = std::bit_cast<std::int64_t>(lhs.value());
            const auto signed_rhs = std::bit_cast<std::int64_t>(rhs.value());
            bool value = false;
            switch (op) {
            case 0x29: value = lhs.value() == rhs.value(); break;
            case 0x2a: value = signed_lhs >= signed_rhs; break;
            case 0x2b: value = signed_lhs > signed_rhs; break;
            case 0x2c: value = signed_lhs <= signed_rhs; break;
            case 0x2d: value = signed_lhs < signed_rhs; break;
            default: value = lhs.value() != rhs.value(); break;
            }
            auto result = push(value ? 1 : 0); if (!result) return result.error(); break;
        }
        case 0x92: { // DW_OP_bregx
            auto number = cfi_uleb(expression, cursor); if (!number) return number.error();
            auto offset = cfi_sleb(expression, cursor); if (!offset) return offset.error();
            const auto id = cfi_register(cpu, number.value());
            if (!id) return failure(ErrorCode::unsupported, "Mach-O CFI expression names an unsupported base register");
            const auto base = reg(context, *id);
            if (!base) return failure(ErrorCode::malformed, "Mach-O CFI expression base register is unavailable");
            std::uint64_t value = 0;
            if (!cfi_add(*base, offset.value(), value)) return failure(ErrorCode::overflow, "Mach-O CFI expression address overflows");
            auto result = push(value); if (!result) return result.error();
            break;
        }
        case 0x90: { // DW_OP_regx
            auto number = cfi_uleb(expression, cursor); if (!number) return number.error();
            auto result = push(0, false, number.value()); if (!result) return result.error();
            break;
        }
        case 0x9c: { // DW_OP_call_frame_cfa
            if (!allow_call_frame_cfa) return failure(ErrorCode::malformed,"Mach-O CFI CFA expression uses circular DW_OP_call_frame_cfa");
            auto result = push(cfa); if (!result) return result.error();
            break;
        }
        default:
            return failure(ErrorCode::unsupported, "Mach-O CFI expression opcode is outside the supported subset");
        }
    }
    if (stack.size() != 1) return failure(ErrorCode::malformed, "Mach-O CFI expression must leave one value");
    if (stack.back().register_location && stack.back().is_value)
        return failure(ErrorCode::malformed, "Mach-O CFI expression cannot mark a register location as a stack value");
    return stack.back();
}

Result<MachOUnwindResult> evaluate_eh_frame(const MachOEhFrameFunction &fde, std::uint32_t cpu,
                                            Address pc, const MachOUnwindContext &context,
                                            const MachOUnwindMemoryReader &read) {
    if (!fde.address || pc.space != fde.address->space || pc.offset < fde.address->offset ||
        pc.offset - fde.address->offset >= fde.size)
        return failure(ErrorCode::out_of_bounds, "PC is outside Mach-O eh_frame FDE range");
    if (!fde.code_alignment) return failure(ErrorCode::malformed, "Mach-O CIE code alignment is zero");
    if (fde.size > UINT64_MAX - fde.address->offset)
        return failure(ErrorCode::overflow, "Mach-O CFI FDE interval overflows");
    CfiState state, initial;
    std::uint64_t location = 0;
    auto run = run_cfi(fde.cie_instructions, cpu, fde.code_alignment, fde.data_alignment, UINT64_MAX, location, state, initial);
    if (!run) return run.error();
    initial = state;
    location = 0;
    run = run_cfi(fde.instructions, cpu, fde.code_alignment, fde.data_alignment,
                  pc.offset - fde.address->offset, location, state, initial,
                  fde.address->offset, fde.size);
    if (!run) return run.error();
    std::uint64_t cfa = 0;
    if (state.cfa_expression) {
        auto value=evaluate_cfi_expression(*state.cfa_expression,cpu,context,0,read,false);
        if(!value)return value.error();
        if(value.value().is_value || value.value().register_location)
            return failure(ErrorCode::malformed,"Mach-O CFI CFA expression ended with a value instead of a location");
        cfa=value.value().value;
    } else {
        if (!state.cfa_register) return failure(ErrorCode::unsupported, "Mach-O CFI does not define a CFA rule");
        const auto cfa_reg = cfi_register(cpu, *state.cfa_register);
        if (!cfa_reg) return failure(ErrorCode::unsupported, "Mach-O CFI CFA register is unsupported");
        const auto base = reg(context, *cfa_reg);
        if (!base) return failure(ErrorCode::malformed, "Mach-O CFI context lacks its CFA register");
        if (!cfi_add(*base, state.cfa_offset, cfa)) return failure(ErrorCode::overflow, "Mach-O CFI CFA overflows");
    }
    MachOUnwindResult result{context, cfa, *fde.address, 0, fde.record_file_offset};
    result.return_address_signed = state.return_address_signed;
    result.gnu_args_size = state.gnu_args_size;
    for (const auto &[number, rule] : state.rules) {
        const auto target = cfi_register(cpu, number);
        if (!target) return failure(ErrorCode::unsupported, "Mach-O CFI rule names a register outside the exposed context");
        switch (rule.kind) {
        case CfiRule::Kind::undefined: result.caller.erase(*target); break;
        case CfiRule::Kind::same: break;
        case CfiRule::Kind::reg: {
            const auto source = cfi_register(cpu, rule.reg);
            if (!source) return failure(ErrorCode::unsupported, "Mach-O CFI register rule names unsupported register");
            const auto value = reg(context, *source);
            if (!value) return failure(ErrorCode::malformed, "Mach-O CFI register rule source is unavailable");
            result.caller[*target] = *value; break;
        }
        case CfiRule::Kind::offset: {
            std::uint64_t at = 0;
            if (!cfi_add(cfa, rule.offset, at)) return failure(ErrorCode::overflow, "Mach-O CFI saved-register address overflows");
            auto value = word(read, at); if (!value) return value.error(); result.caller[*target] = value.value(); break;
        }
        case CfiRule::Kind::value_offset: {
            std::uint64_t value = 0;
            if (!cfi_add(cfa, rule.offset, value)) return failure(ErrorCode::overflow, "Mach-O CFI value offset overflows");
            result.caller[*target] = value;
            break;
        }
        case CfiRule::Kind::expression:
        case CfiRule::Kind::value_expression: {
            auto value = evaluate_cfi_expression(rule.expression, cpu, context, cfa, read, false);
            if (!value) return value.error();
            if (value.value().register_location) {
                if (rule.kind != CfiRule::Kind::expression)
                    return failure(ErrorCode::malformed, "Mach-O CFI value-expression ended with a register location");
                const auto source = cfi_register(cpu, *value.value().register_location);
                if (!source)
                    return failure(ErrorCode::unsupported, "Mach-O CFI expression names an unsupported register location");
                const auto contents = reg(context, *source);
                if (!contents)
                    return failure(ErrorCode::malformed, "Mach-O CFI expression register location is unavailable");
                result.caller[*target] = *contents;
            } else if (rule.kind == CfiRule::Kind::expression && !value.value().is_value) {
                auto saved = word(read, value.value().value);
                if (!saved) return saved.error();
                result.caller[*target] = saved.value();
            } else {
                result.caller[*target] = value.value().value;
            }
            ++result.expression_rules_evaluated;
            break;
        }
        }
    }
    const auto return_reg = cfi_register(cpu, fde.return_register);
    if (!return_reg) return failure(ErrorCode::unsupported, "Mach-O CIE return-address register is unsupported");
    const auto return_address = reg(result.caller, *return_reg);
    if (!return_address) return failure(ErrorCode::malformed, "Mach-O CFI does not recover a return address");
    if (cpu == arm64_cpu) result.caller[MachOUnwindRegister::arm64_pc] = *return_address;
    else result.caller[MachOUnwindRegister::x86_64_rip] = *return_address;
    if (cpu == x86_64_cpu) result.caller[MachOUnwindRegister::x86_64_rsp] = cfa;
    else result.caller[MachOUnwindRegister::arm64_sp] = cfa;
    return result;
}

Result<std::vector<unsigned>> permutation(std::uint32_t rank, unsigned count) {
    constexpr unsigned values[] = {1, 2, 3, 4, 5, 6};
    std::vector<unsigned> available(std::begin(values), std::end(values));
    std::vector<unsigned> decoded;
    for (unsigned i = 0; i < count; ++i) {
        unsigned weight = 1;
        for (unsigned k = 0; k < count - i - 1; ++k) weight *= static_cast<unsigned>(available.size()) - 1 - k;
        const auto choice = weight ? rank / weight : 0;
        if (choice >= available.size())
            return failure(ErrorCode::malformed, "Mach-O x86_64 register permutation is out of range");
        rank = weight ? rank % weight : rank;
        decoded.push_back(available[choice]);
        available.erase(available.begin() + static_cast<std::ptrdiff_t>(choice));
    }
    if (rank != 0)
        return failure(ErrorCode::malformed, "Mach-O x86_64 register permutation has unused rank bits");
    return decoded;
}

MachOUnwindRegister x86_register(unsigned encoded) {
    if (encoded == 6) return MachOUnwindRegister::x86_64_rbp;
    return static_cast<MachOUnwindRegister>(static_cast<unsigned>(MachOUnwindRegister::x86_64_rbx) + encoded - 1);
}

Result<MachOUnwindResult> evaluate_x86(const MachOCompactUnwindFunction &fn,
                                        const MachOUnwindContext &context,
                                        const MachOUnwindMemoryReader &read,
                                        std::uint64_t function_size) {
    const auto encoding = fn.encoding;
    const auto mode = encoding & mode_mask;
    MachOUnwindResult result{context, 0, *fn.address, encoding, fn.record_file_offset};
    std::uint64_t cfa = 0, slot = 0;
    if (mode == 0x01000000u) { // RBP frame
        const auto rbp = reg(context, MachOUnwindRegister::x86_64_rbp);
        if (!rbp) return failure(ErrorCode::malformed, "Mach-O x86_64 unwind context lacks RBP");
        if ((encoding & 0x00008000u) != 0)
            return failure(ErrorCode::malformed, "Mach-O x86_64 RBP frame has a reserved register field");
        std::uint32_t fields = encoding & 0x7fffu;
        const auto offset = (encoding >> 16) & 0xffu;
        std::vector<MachOUnwindRegister> saved_registers;
        for (unsigned i = 0; i < 5; ++i) {
            const auto code = fields & 7u;
            if (code > 5) return failure(ErrorCode::malformed, "Mach-O x86_64 RBP frame names an invalid saved register");
            if (code) {
                if (offset < i + 1)
                    return failure(ErrorCode::malformed, "Mach-O x86_64 RBP save slot overlaps its frame record");
                if (std::find(saved_registers.begin(), saved_registers.end(), x86_register(code)) != saved_registers.end())
                    return failure(ErrorCode::malformed, "Mach-O x86_64 RBP frame repeats a saved register");
                saved_registers.push_back(x86_register(code));
            }
            fields >>= 3;
        }
        if (!saved_registers.empty() && offset < saved_registers.size())
            return failure(ErrorCode::malformed, "Mach-O x86_64 RBP save area overlaps its frame record");
        if (!sub(*rbp, std::uint64_t(offset) * 8, slot))
            return failure(ErrorCode::overflow, "Mach-O x86_64 saved-register area underflows");
        for (unsigned i = 0; i < 5; ++i) {
            const auto code = (encoding >> (i * 3)) & 7u;
            if (!code) { if (!add(slot, 8, slot)) return failure(ErrorCode::overflow, "Mach-O x86_64 save area overflows"); continue; }
            auto value = word(read, slot);
            if (!value) return value.error();
            result.caller[x86_register(code)] = value.value();
            if (!add(slot, 8, slot)) return failure(ErrorCode::overflow, "Mach-O x86_64 save area overflows");
        }
        if (!add(*rbp, 16, cfa) || !sub(cfa, 16, slot))
            return failure(ErrorCode::overflow, "Mach-O x86_64 RBP frame address overflows");
        auto saved = word(read, slot);
        if (!saved) return saved.error();
        result.caller[MachOUnwindRegister::x86_64_rbp] = saved.value();
        if (!sub(cfa, 8, slot)) return failure(ErrorCode::overflow, "Mach-O x86_64 return slot underflows");
        auto pc = word(read, slot);
        if (!pc) return pc.error();
        result.caller[MachOUnwindRegister::x86_64_rip] = pc.value();
        result.caller[MachOUnwindRegister::x86_64_rsp] = cfa;
    } else if (mode == 0x02000000u || mode == 0x03000000u) { // immediate/indirect stack allocation
        const auto count = (encoding >> 10) & 7u;
        if (mode == 0x02000000u && (encoding & 0x0000e000u) != 0)
            return failure(ErrorCode::malformed, "Mach-O x86_64 stack mode has nonzero reserved bits");
        auto regs = permutation(encoding & 0x3ffu, count);
        if (!regs) return regs.error();
        const auto rsp = reg(context, MachOUnwindRegister::x86_64_rsp);
        if (!rsp) return failure(ErrorCode::malformed, "Mach-O x86_64 unwind context lacks RSP");
        std::uint64_t stack = std::uint64_t((encoding >> 16) & 0xffu) * 8;
        if (mode == 0x03000000u) {
            // The encoded field is a byte offset to the imm32 operand in the
            // prologue's `subq $imm32, %rsp`, not an address in the stack.
            const auto immediate_offset = std::uint64_t((encoding >> 16) & 0xffu);
            if (immediate_offset < 3 || immediate_offset > function_size ||
                function_size - immediate_offset < 4)
                return failure(ErrorCode::malformed, "Mach-O x86_64 indirect stack immediate is outside its function interval");
            std::uint64_t instruction_address = 0;
            if (!add(fn.address->offset, immediate_offset - 3, instruction_address))
                return failure(ErrorCode::overflow, "Mach-O x86_64 indirect stack instruction address overflows");
            auto instruction = read(instruction_address, 7);
            if (!instruction) return failure(ErrorCode::out_of_bounds, "Mach-O x86_64 indirect stack prologue is unreadable");
            if ((*instruction & 0x00ffffffu) != 0x00ec8148u)
                return failure(ErrorCode::malformed, "Mach-O x86_64 indirect stack encoding does not point at `subq imm32, %rsp`");
            const auto immediate = static_cast<std::uint32_t>(*instruction >> 24);
            if (immediate > static_cast<std::uint32_t>(INT32_MAX))
                return failure(ErrorCode::malformed, "Mach-O x86_64 indirect stack adjustment is negative");
            const auto stack_adjust = std::uint64_t((encoding >> 13) & 7u) * 8;
            if (immediate > UINT64_MAX - stack_adjust)
                return failure(ErrorCode::overflow, "Mach-O x86_64 indirect stack adjustment overflows");
            stack = immediate + stack_adjust;
            if (stack <= 2048 || (stack & 7u) != 0)
                return failure(ErrorCode::malformed, "Mach-O x86_64 indirect stack size is not a large aligned frame");
        }
        if (stack < std::uint64_t(count + 1) * 8)
            return failure(ErrorCode::malformed, "Mach-O x86_64 stack is smaller than saved registers and return slot");
        if (!add(*rsp, stack, cfa) || !sub(cfa, 8 + std::uint64_t(count) * 8, slot))
            return failure(ErrorCode::overflow, "Mach-O x86_64 frameless stack address overflows");
        for (const auto code : regs.value()) {
            auto value = word(read, slot);
            if (!value) return value.error();
            result.caller[x86_register(code)] = value.value();
            if (!add(slot, 8, slot)) return failure(ErrorCode::overflow, "Mach-O x86_64 saved-register area overflows");
        }
        auto pc = word(read, slot);
        if (!pc) return pc.error();
        result.caller[MachOUnwindRegister::x86_64_rip] = pc.value();
        result.caller[MachOUnwindRegister::x86_64_rsp] = cfa;
    } else if (mode == 0x04000000u) {
        return failure(ErrorCode::unsupported, "Mach-O x86_64 DWARF FDE evaluation is not implemented");
    } else {
        return failure(ErrorCode::unsupported, "Mach-O x86_64 compact-unwind mode is unsupported");
    }
    result.cfa = cfa;
    return result;
}

Result<MachOUnwindResult> evaluate_arm64(const MachOCompactUnwindFunction &fn,
                                          const MachOUnwindContext &context,
                                          const MachOUnwindMemoryReader &read,
                                          Address pc, bool arm64e, std::uint64_t function_size) {
    const auto encoding = fn.encoding;
    const auto mode = encoding & mode_mask;
    if (mode == 0x03000000u)
        return failure(ErrorCode::unsupported, "Mach-O arm64 DWARF FDE evaluation is not implemented");
    const bool pauth_frame = mode == 0x05000000u;
    if (mode != 0x02000000u && mode != 0x04000000u && !pauth_frame)
        return failure(ErrorCode::unsupported, "Mach-O arm64 compact-unwind mode is unsupported");
    if (pauth_frame && !arm64e)
        return failure(ErrorCode::unsupported, "Mach-O authenticated compact-unwind recipe requires an arm64e slice");
    const auto x_pairs = encoding & 0x1fu;
    const auto d_pairs = encoding & 0x0f00u;
    if ((encoding & 0x000000e0u) != 0 || (mode == 0x04000000u && (encoding & 0x00fff000u) != 0))
        return failure(ErrorCode::malformed, "Mach-O arm64 compact-unwind reserved fields are nonzero");
    MachOUnwindResult result{context, 0, *fn.address, encoding, fn.record_file_offset};
    if (mode == 0x02000000u) { // frameless leaf: LR remains in X30
        const auto sp = reg(context, MachOUnwindRegister::arm64_sp);
        const auto lr = reg(context, MachOUnwindRegister::arm64_x30);
        if (!sp || !lr) return failure(ErrorCode::malformed, "Mach-O arm64 frameless context lacks SP or X30");
        std::uint64_t cursor = 0;
        const auto stack = std::uint64_t((encoding >> 12) & 0xfffu) * 16;
        if (stack < std::uint64_t(std::popcount(x_pairs) + std::popcount(d_pairs)) * 16)
            return failure(ErrorCode::malformed, "Mach-O arm64 frameless stack is smaller than its saved-register pairs");
        if (!add(*sp, stack, cursor))
            return failure(ErrorCode::overflow, "Mach-O arm64 frameless stack address overflows");
        for (unsigned pair = 0; pair < 5; ++pair) {
            if (!(x_pairs & (1u << pair))) continue;
            const auto first_reg = static_cast<MachOUnwindRegister>(static_cast<unsigned>(MachOUnwindRegister::arm64_x19) + pair * 2);
            if (cursor < 16) return failure(ErrorCode::overflow, "Mach-O arm64 saved-register area underflows");
            cursor -= 8;
            auto first = word(read, cursor); if (!first) return first.error();
            cursor -= 8;
            auto second = word(read, cursor); if (!second) return second.error();
            result.caller[first_reg] = first.value();
            result.caller[static_cast<MachOUnwindRegister>(static_cast<unsigned>(first_reg) + 1)] = second.value();
        }
        for (unsigned pair = 0; pair < 4; ++pair) {
            if (!(d_pairs & (1u << (pair + 8)))) continue;
            const auto first_reg = static_cast<MachOUnwindRegister>(static_cast<unsigned>(MachOUnwindRegister::arm64_d8) + pair * 2);
            if (cursor < 16) return failure(ErrorCode::overflow, "Mach-O arm64 vector save area underflows");
            cursor -= 8;
            auto first = word(read, cursor); if (!first) return first.error();
            cursor -= 8;
            auto second = word(read, cursor); if (!second) return second.error();
            result.caller[first_reg] = first.value();
            result.caller[static_cast<MachOUnwindRegister>(static_cast<unsigned>(first_reg) + 1)] = second.value();
        }
        result.cfa = cursor;
        result.caller[MachOUnwindRegister::arm64_sp] = cursor;
        result.caller[MachOUnwindRegister::arm64_pc] = *lr;
        return result;
    }
    const auto fp = reg(context, MachOUnwindRegister::arm64_x29);
    if (!fp) return failure(ErrorCode::malformed, "Mach-O arm64 unwind context lacks X29");
    std::uint64_t cfa = 0, slot = 0;
    if (!add(*fp, 16, cfa) || !sub(*fp, 8, slot))
        return failure(ErrorCode::overflow, "Mach-O arm64 frame address overflows");
    result.cfa = cfa;
    for (unsigned pair = 0; pair < 5; ++pair) {
        if (!(x_pairs & (1u << pair))) continue;
        if (slot < 8) return failure(ErrorCode::overflow, "Mach-O arm64 saved-register area underflows");
        const auto first_reg = static_cast<MachOUnwindRegister>(static_cast<unsigned>(MachOUnwindRegister::arm64_x19) + pair * 2);
        auto first = word(read, slot); if (!first) return first.error();
        slot -= 8;
        auto second = word(read, slot); if (!second) return second.error();
        result.caller[first_reg] = first.value();
        result.caller[static_cast<MachOUnwindRegister>(static_cast<unsigned>(first_reg) + 1)] = second.value();
        if (slot < 8) return failure(ErrorCode::overflow, "Mach-O arm64 saved-register area underflows");
        slot -= 8;
    }
    for (unsigned pair = 0; pair < 4; ++pair) {
        if (!(d_pairs & (1u << (pair + 8)))) continue;
        if (slot < 8) return failure(ErrorCode::overflow, "Mach-O arm64 vector save area underflows");
        const auto first_reg = static_cast<MachOUnwindRegister>(static_cast<unsigned>(MachOUnwindRegister::arm64_d8) + pair * 2);
        auto first = word(read, slot); if (!first) return first.error();
        slot -= 8;
        if (slot < 8) return failure(ErrorCode::overflow, "Mach-O arm64 vector save area underflows");
        auto second = word(read, slot); if (!second) return second.error();
        result.caller[first_reg] = first.value();
        result.caller[static_cast<MachOUnwindRegister>(static_cast<unsigned>(first_reg) + 1)] = second.value();
        slot -= 8;
    }
    auto old_fp = word(read, *fp);
    if (!old_fp) return old_fp.error();
    std::uint64_t lr_at = 0;
    if (!add(*fp, 8, lr_at)) return failure(ErrorCode::overflow, "Mach-O arm64 return slot overflows");
    auto lr = word(read, lr_at);
    if (!lr) return lr.error();
    result.caller[MachOUnwindRegister::arm64_x29] = old_fp.value();
    result.caller[MachOUnwindRegister::arm64_x30] = lr.value();
    result.caller[MachOUnwindRegister::arm64_sp] = cfa;
    result.caller[MachOUnwindRegister::arm64_pc] = lr.value();
    if (pauth_frame) {
        // The field is a byte offset, aligned by the encoding to an AArch64
        // instruction. The LR is signed after that pacibsppc instruction has
        // executed. We report that state only; pointer authentication itself
        // is intentionally outside this evaluator.
        // Bits 12..23 hold the offset in instruction-word units.
        const auto pac_offset = std::uint64_t((encoding & 0x00fff000u) >> 10);
        if (pac_offset >= function_size)
            return failure(ErrorCode::malformed, "Mach-O authenticated unwind PAC offset is outside its function interval");
        if (pc.offset < fn.address->offset)
            return failure(ErrorCode::out_of_bounds, "Mach-O authenticated unwind PC precedes its function");
        if (pc.offset - fn.address->offset <= pac_offset)
            return failure(ErrorCode::unsupported, "Mach-O authenticated compact-unwind prologue has not reached its PAC instruction");
        result.return_address_signed = true;
    }
    return result;
}
} // namespace

Result<MachOUnwindResult> evaluate_macho_unwind(const MachOMetadata &metadata, Address pc,
                                                const MachOUnwindContext &context,
                                                const MachOUnwindMemoryReader &read) {
    if (metadata.selected_slice >= metadata.container.slices.size())
        return failure(ErrorCode::malformed, "Mach-O selected slice is invalid");
    const auto cpu = metadata.container.slices[metadata.selected_slice].header.cpu_type;
    const MachOEhFrameFunction *fde_match = nullptr;
    for (const auto &fde : metadata.eh_frame_functions) {
        if (!fde.address || fde.address->space != pc.space || pc.offset < fde.address->offset ||
            pc.offset - fde.address->offset >= fde.size) continue;
        if (fde_match) return failure(ErrorCode::malformed, "Mach-O eh_frame FDE ranges overlap at PC");
        fde_match = &fde;
    }
    if (fde_match) return evaluate_eh_frame(*fde_match, cpu, pc, context, read);
    const MachOCompactUnwindFunction *found = nullptr;
    for (const auto &fn : metadata.compact_unwind_functions) {
        if (!fn.address || fn.address->space != pc.space) continue;
        if (fn.address->offset <= pc.offset && (!found || fn.address->offset > found->address->offset))
            found = &fn;
        else if (found && fn.section == found->section && fn.address->offset == found->address->offset)
            return failure(ErrorCode::malformed, "Mach-O compact-unwind metadata has duplicate function entries");
    }
    if (!found) return failure(ErrorCode::out_of_bounds, "No Mach-O compact-unwind entry precedes PC");
    const MachOCompactUnwindFunction *next = nullptr;
    for (const auto &fn : metadata.compact_unwind_functions) {
        if (!fn.address || fn.section != found->section || fn.address->space != pc.space ||
            fn.address->offset <= found->address->offset) continue;
        if (!next || fn.address->offset < next->address->offset) next = &fn;
        else if (fn.address->offset == next->address->offset)
            return failure(ErrorCode::malformed, "Mach-O compact-unwind metadata has duplicate function boundaries");
    }
    if (!next || pc.offset >= next->address->offset)
        return failure(ErrorCode::out_of_bounds, "Mach-O compact-unwind function interval is not proven");
    if (cpu == x86_64_cpu)
        return evaluate_x86(*found, context, read, next->address->offset - found->address->offset);
    if (cpu == arm64_cpu) {
        constexpr std::uint32_t cpu_subtype_arm64e = 2u;
        constexpr std::uint32_t cpu_subtype_mask = 0x00ffffffu;
        const auto subtype = metadata.container.slices[metadata.selected_slice].header.cpu_subtype & cpu_subtype_mask;
        return evaluate_arm64(*found, context, read, pc, subtype == cpu_subtype_arm64e,
                              next->address->offset - found->address->offset);
    }
    return failure(ErrorCode::unsupported, "Mach-O CPU has no runtime compact-unwind evaluator");
}
} // namespace hexlab
