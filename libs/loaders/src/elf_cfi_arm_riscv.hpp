#pragma once

#include <bit>
#include <memory>
#include <new>
#include <span>
#include <vector>

// Integer-only ELF CFI. Keep this separate from the 64-bit Mach-O bridge:
// ARM32/RV32 operands, addresses and saved words must retain their own width.
namespace hexlab {
namespace {
struct ElfCfiFailure { Error error; };
void elf_cfi_require(bool valid, ErrorCode code, const char *message) {
    if (!valid) throw ElfCfiFailure{{code, message}};
}

struct ElfCfiCursor {
    std::span<const std::byte> bytes;
    ByteOrder order;
    std::size_t at = 0;
    std::uint64_t fixed(unsigned width) {
        elf_cfi_require(width <= bytes.size() - at, ErrorCode::malformed, "Truncated ELF CFI operand");
        std::uint64_t value = 0;
        for (unsigned i = 0; i < width; ++i) {
            const auto index = order == ByteOrder::big ? i : width - 1 - i;
            value = (value << 8) | std::to_integer<unsigned>(bytes[at + index]);
        }
        at += width;
        return value;
    }
    std::uint64_t uleb() {
        std::uint64_t value = 0;
        for (unsigned i = 0; i < 10; ++i) {
            const auto byte = fixed(1);
            elf_cfi_require(i != 9 || (byte & 0xfe) == 0, ErrorCode::overflow, "ELF CFI ULEB overflows");
            value |= (byte & 0x7f) << (i * 7);
            if (!(byte & 0x80)) return value;
        }
        throw ElfCfiFailure{{ErrorCode::malformed, "ELF CFI ULEB exceeds ten bytes"}};
    }
    std::int64_t sleb() {
        std::uint64_t value = 0;
        for (unsigned i = 0; i < 10; ++i) {
            const auto byte = fixed(1);
            elf_cfi_require(i != 9 || byte == 0 || byte == 0x7f,
                ErrorCode::overflow, "ELF CFI SLEB overflows");
            value |= (byte & 0x7f) << (i * 7);
            if (!(byte & 0x80)) {
                const auto bits = (i + 1) * 7;
                if (bits < 64 && (byte & 0x40)) value |= UINT64_MAX << bits;
                return std::bit_cast<std::int64_t>(value);
            }
        }
        throw ElfCfiFailure{{ErrorCode::malformed, "ELF CFI SLEB exceeds ten bytes"}};
    }
    std::shared_ptr<const std::vector<std::byte>> block() {
        const auto length = uleb();
        elf_cfi_require(length <= 64 * 1024, ErrorCode::resource_limit,
                        "ELF CFI expression exceeds 64 KiB");
        elf_cfi_require(length <= bytes.size() - at, ErrorCode::malformed,
                        "Truncated ELF CFI expression block");
        auto result = std::make_shared<std::vector<std::byte>>(
            bytes.begin() + static_cast<std::ptrdiff_t>(at),
            bytes.begin() + static_cast<std::ptrdiff_t>(at + static_cast<std::size_t>(length)));
        at += static_cast<std::size_t>(length);
        return result;
    }
};
struct ElfCfiRule {
    enum class Kind { offset, value_offset, same, undefined, reg, expression, value_expression } kind = Kind::same;
    std::int64_t offset = 0;
    std::uint64_t source = 0;
    std::shared_ptr<const std::vector<std::byte>> expression;
};
struct ElfCfiState {
    std::optional<std::uint64_t> cfa_register;
    std::int64_t cfa_offset = 0;
    std::shared_ptr<const std::vector<std::byte>> cfa_expression;
    std::map<std::uint64_t, ElfCfiRule> rules;
};

std::int64_t elf_cfi_scale(std::int64_t factor, std::int64_t alignment) {
    if (!factor || !alignment) return 0;
    const auto a = factor < 0 ? std::uint64_t(-(factor + 1)) + 1 : std::uint64_t(factor);
    const auto b = alignment < 0 ? std::uint64_t(-(alignment + 1)) + 1 : std::uint64_t(alignment);
    elf_cfi_require(a <= std::uint64_t(INT64_MAX) / b, ErrorCode::overflow, "ELF CFI scaled offset overflows");
    const auto magnitude = static_cast<std::int64_t>(a * b);
    return (factor < 0) != (alignment < 0) ? -magnitude : magnitude;
}
std::uint64_t elf_cfi_add(std::uint64_t base, std::int64_t delta, std::uint64_t limit) {
    elf_cfi_require(base <= limit, ErrorCode::overflow, "ELF CFI address exceeds target width");
    if (delta >= 0) {
        elf_cfi_require(std::uint64_t(delta) <= limit - base, ErrorCode::overflow, "ELF CFI address overflows");
        return base + std::uint64_t(delta);
    }
    const auto magnitude = std::uint64_t(-(delta + 1)) + 1;
    elf_cfi_require(magnitude <= base, ErrorCode::overflow, "ELF CFI address underflows");
    return base - magnitude;
}

std::uint64_t evaluate_elf_cfi_expression(std::span<const std::byte> expression, ByteOrder order,
    std::uint8_t width, std::uint64_t limit, const ElfUnwindContext &registers,
    const ElfUnwindMemoryReader &read, std::optional<std::uint64_t> cfa,
    bool seed_cfa, bool riscv, std::size_t &operations) {
    elf_cfi_require(!expression.empty(), ErrorCode::malformed, "ELF CFI expression is empty");
    elf_cfi_require(width == 4 || width == 8, ErrorCode::unsupported,
                    "ELF CFI expression address width is unsupported");
    ElfCfiCursor cursor{expression, order};
    std::vector<std::uint64_t> stack;
    stack.reserve(16);
    if (seed_cfa) {
        elf_cfi_require(cfa.has_value(), ErrorCode::unsupported,
                        "ELF CFI register expression requires a computed CFA");
        stack.push_back(*cfa);
    }
    const auto push = [&](std::uint64_t value) {
        elf_cfi_require(stack.size() < 64, ErrorCode::resource_limit,
                        "ELF CFI expression stack exceeds 64 entries");
        elf_cfi_require(value <= limit, ErrorCode::overflow,
                        "ELF CFI expression value exceeds target width");
        stack.push_back(value);
    };
    const auto push_signed = [&](std::int64_t value) {
        if (width == 4)
            elf_cfi_require(value >= INT32_MIN && value <= INT32_MAX, ErrorCode::overflow,
                            "ELF CFI signed expression constant exceeds target width");
        push(static_cast<std::uint64_t>(value) & limit);
    };
    const auto pop = [&]() {
        elf_cfi_require(!stack.empty(), ErrorCode::malformed,
                        "ELF CFI expression stack underflows");
        const auto value = stack.back();
        stack.pop_back();
        return value;
    };
    const auto register_value = [&](std::uint64_t number) {
        elf_cfi_require(number <= (riscv ? 31u : 15u), ErrorCode::unsupported,
                        "ELF CFI expression register is outside the integer context");
        if (riscv && number == 0) {
            const auto found = registers.find(0);
            elf_cfi_require(found == registers.end() || found->second == 0, ErrorCode::malformed,
                            "ELF CFI expression context has nonzero RISC-V x0");
            return std::uint64_t{0};
        }
        const auto found = registers.find(number);
        elf_cfi_require(found != registers.end(), ErrorCode::out_of_bounds,
                        "ELF CFI expression references an unavailable register");
        elf_cfi_require(found->second <= limit, ErrorCode::overflow,
                        "ELF CFI expression register exceeds target width");
        return found->second;
    };
    while (cursor.at < expression.size()) {
        elf_cfi_require(++operations <= 65536, ErrorCode::resource_limit,
                        "ELF CFI exceeds the 65536 operation limit");
        const auto op = static_cast<unsigned>(cursor.fixed(1));
        if (op >= 0x30 && op <= 0x4f) {
            push(op - 0x30);
            continue;
        }
        if (op >= 0x70 && op <= 0x8f) { // DW_OP_breg0..31
            const auto base = register_value(op - 0x70);
            push((base + static_cast<std::uint64_t>(cursor.sleb())) & limit);
            continue;
        }
        switch (op) {
        case 0x03: // DW_OP_addr
            push(cursor.fixed(width));
            break;
        case 0x06: { // DW_OP_deref
            const auto address = pop();
            elf_cfi_require(width - 1u <= limit - address, ErrorCode::overflow,
                            "ELF CFI expression dereference crosses target width");
            elf_cfi_require(static_cast<bool>(read), ErrorCode::invalid_argument,
                            "ELF CFI expression requires a memory reader");
            const auto value = read(address, width);
            elf_cfi_require(value.has_value(), ErrorCode::out_of_bounds,
                            "ELF CFI expression dereference is unavailable");
            elf_cfi_require(*value <= limit, ErrorCode::overflow,
                            "ELF CFI expression dereference exceeds target width");
            push(*value);
            break;
        }
        case 0x08: push(cursor.fixed(1)); break; // DW_OP_const1u
        case 0x09: push_signed(std::bit_cast<std::int8_t>(
                            static_cast<std::uint8_t>(cursor.fixed(1)))); break; // DW_OP_const1s
        case 0x0a: push(cursor.fixed(2)); break; // DW_OP_const2u
        case 0x0b: push_signed(std::bit_cast<std::int16_t>(
                            static_cast<std::uint16_t>(cursor.fixed(2)))); break; // DW_OP_const2s
        case 0x0c: push(cursor.fixed(4)); break; // DW_OP_const4u
        case 0x0d: push_signed(std::bit_cast<std::int32_t>(
                            static_cast<std::uint32_t>(cursor.fixed(4)))); break; // DW_OP_const4s
        case 0x0e: push(cursor.fixed(8)); break; // DW_OP_const8u
        case 0x0f: push_signed(std::bit_cast<std::int64_t>(cursor.fixed(8))); break; // DW_OP_const8s
        case 0x10: push(cursor.uleb()); break; // DW_OP_constu
        case 0x11: push_signed(cursor.sleb()); break; // DW_OP_consts
        case 0x12: // DW_OP_dup
            elf_cfi_require(!stack.empty(), ErrorCode::malformed, "DW_OP_dup requires one stack item");
            push(stack.back());
            break;
        case 0x13: (void)pop(); break; // DW_OP_drop
        case 0x14: // DW_OP_over
            elf_cfi_require(stack.size() >= 2, ErrorCode::malformed, "DW_OP_over requires two stack items");
            push(stack[stack.size() - 2]);
            break;
        case 0x15: { // DW_OP_pick
            const auto depth = cursor.fixed(1);
            elf_cfi_require(depth < stack.size(), ErrorCode::malformed,
                            "DW_OP_pick index is outside the expression stack");
            push(stack[stack.size() - 1 - static_cast<std::size_t>(depth)]);
            break;
        }
        case 0x16: // DW_OP_swap
            elf_cfi_require(stack.size() >= 2, ErrorCode::malformed, "DW_OP_swap requires two stack items");
            std::swap(stack[stack.size() - 1], stack[stack.size() - 2]);
            break;
        case 0x17: { // DW_OP_rot
            elf_cfi_require(stack.size() >= 3, ErrorCode::malformed, "DW_OP_rot requires three stack items");
            const auto first = stack[stack.size() - 3];
            stack[stack.size() - 3] = stack[stack.size() - 2];
            stack[stack.size() - 2] = stack.back();
            stack.back() = first;
            break;
        }
        case 0x1c: { // DW_OP_minus
            const auto right = pop(), left = pop();
            push((left - right) & limit);
            break;
        }
        case 0x1f: push((std::uint64_t{0} - pop()) & limit); break; // DW_OP_neg
        case 0x20: push(~pop() & limit); break; // DW_OP_not
        case 0x22: { // DW_OP_plus
            const auto right = pop(), left = pop();
            push((left + right) & limit);
            break;
        }
        case 0x23: { // DW_OP_plus_uconst
            const auto addend = cursor.uleb(), value = pop();
            elf_cfi_require(addend <= limit, ErrorCode::overflow,
                            "DW_OP_plus_uconst constant exceeds target width");
            push((value + addend) & limit);
            break;
        }
        case 0x90: { // DW_OP_regx is a register location; do not guess a value
            elf_cfi_require(false, ErrorCode::unsupported,
                            "ELF CFI expression register-location operators are unsupported");
            break;
        }
        case 0x92: { // DW_OP_bregx
            const auto number = cursor.uleb();
            const auto base = register_value(number);
            push((base + static_cast<std::uint64_t>(cursor.sleb())) & limit);
            break;
        }
        case 0x96: break; // DW_OP_nop
        case 0x9c: // DW_OP_call_frame_cfa is excluded by the CFI-expression subset.
            elf_cfi_require(false, ErrorCode::unsupported,
                            "DW_OP_call_frame_cfa is unsupported in ELF CFI expressions");
            break;
        default:
            throw ElfCfiFailure{{ErrorCode::unsupported,
                "ELF CFI expression opcode is outside the bounded integer subset"}};
        }
    }
    elf_cfi_require(!stack.empty(), ErrorCode::malformed,
                    "ELF CFI expression produces no result");
    return stack.back();
}

void run_elf_integer_cfi(std::span<const std::byte> program, ByteOrder order, bool arm,
    std::uint64_t code_alignment, std::int64_t data_alignment, std::uint64_t target,
    std::uint64_t limit, ElfCfiState &state, const ElfCfiState &initial, std::size_t &operations) {
    ElfCfiCursor cursor{program, order};
    std::uint64_t location = 0;
    std::vector<ElfCfiState> saved;
    const auto register_number = [&]() {
        const auto number = cursor.uleb();
        elf_cfi_require(number <= (arm ? 15u : 31u), ErrorCode::unsupported, "ELF CFI register is outside the integer context");
        return number;
    };
    const auto unsigned_factor = [&]() {
        const auto factor = cursor.uleb();
        elf_cfi_require(factor <= std::uint64_t(INT64_MAX), ErrorCode::overflow, "ELF CFI offset factor overflows");
        return static_cast<std::int64_t>(factor);
    };
    const auto restore = [&](std::uint64_t number) {
        if (const auto rule = initial.rules.find(number); rule != initial.rules.end()) state.rules[number] = rule->second;
        else state.rules.erase(number);
    };
    while (cursor.at < program.size()) {
        elf_cfi_require(++operations <= 65536, ErrorCode::resource_limit, "ELF CFI exceeds the 65536 operation limit");
        const auto op = static_cast<unsigned>(cursor.fixed(1));
        const auto primary = op & 0xc0;
        if (primary == 0x40 || op == 2 || op == 3 || op == 4) {
            const auto delta = primary == 0x40 ? op & 0x3fu : cursor.fixed(op == 2 ? 1 : op == 3 ? 2 : 4);
            elf_cfi_require(!delta || code_alignment <= limit / delta, ErrorCode::overflow, "ELF CFI location advance overflows");
            const auto advance = delta * code_alignment;
            elf_cfi_require(advance <= limit - location, ErrorCode::overflow, "ELF CFI location exceeds target width");
            if (location + advance > target) return;
            location += advance;
            continue;
        }
        if (primary == 0x80 || primary == 0xc0) {
            const auto number = op & 0x3fu;
            elf_cfi_require(number <= (arm ? 15u : 31u), ErrorCode::unsupported, "ELF CFI rule names an unsupported register");
            if (primary == 0xc0) restore(number);
            else state.rules[number] = {ElfCfiRule::Kind::offset, elf_cfi_scale(unsigned_factor(), data_alignment), 0};
            continue;
        }
        switch (op) {
        case 0: break; // DW_CFA_nop
        case 5: case 6: case 7: case 8: {
            const auto number = register_number();
            if (op == 5) state.rules[number] = {ElfCfiRule::Kind::offset, elf_cfi_scale(unsigned_factor(), data_alignment), 0};
            else if (op == 6) restore(number);
            else state.rules[number] = {op == 7 ? ElfCfiRule::Kind::undefined : ElfCfiRule::Kind::same, 0, 0};
            break;
        }
        case 9: {
            const auto number = register_number();
            state.rules[number] = {ElfCfiRule::Kind::reg, 0, register_number()};
            break;
        }
        case 10:
            elf_cfi_require(saved.size() < 64, ErrorCode::resource_limit, "ELF CFI remember_state nesting exceeds 64");
            saved.push_back(state);
            break;
        case 11:
            elf_cfi_require(!saved.empty(), ErrorCode::malformed, "ELF CFI restore_state has no saved state");
            state = std::move(saved.back());
            saved.pop_back();
            break;
        case 12: case 18:
            state.cfa_register = register_number();
            state.cfa_offset = op == 12 ? unsigned_factor() : elf_cfi_scale(cursor.sleb(), data_alignment);
            state.cfa_expression.reset();
            break;
        case 15: // DW_CFA_def_cfa_expression
            state.cfa_register.reset();
            state.cfa_offset = 0;
            state.cfa_expression = cursor.block();
            break;
        case 13:
            elf_cfi_require(state.cfa_register.has_value(), ErrorCode::malformed, "ELF CFI def_cfa_register has no CFA rule");
            state.cfa_register = register_number();
            break;
        case 14: case 19:
            elf_cfi_require(state.cfa_register.has_value(), ErrorCode::malformed, "ELF CFI def_cfa_offset has no CFA rule");
            state.cfa_offset = op == 14 ? unsigned_factor() : elf_cfi_scale(cursor.sleb(), data_alignment);
            break;
        case 17: case 20: case 21: {
            const auto number = register_number();
            const auto factor = op == 20 ? unsigned_factor() : cursor.sleb();
            state.rules[number] = {op == 17 ? ElfCfiRule::Kind::offset : ElfCfiRule::Kind::value_offset,
                elf_cfi_scale(factor, data_alignment), 0};
            break;
        }
        case 16: case 22: { // DW_CFA_expression / DW_CFA_val_expression
            const auto number = register_number();
            auto expression = cursor.block();
            state.rules[number] = {op == 16 ? ElfCfiRule::Kind::expression : ElfCfiRule::Kind::value_expression,
                0, 0, std::move(expression)};
            break;
        }
        default:
            throw ElfCfiFailure{{ErrorCode::unsupported, "ARM/RISC-V ELF CFI opcode is outside the integer rule subset"}};
        }
    }
}

Result<ElfUnwindResult> evaluate_elf_integer_unwind(const ElfMetadata &metadata, const ElfEhFrameFunction &fde,
    Address pc, const ElfUnwindContext &context, const ElfUnwindMemoryReader &read) {
    try {
        const bool arm = metadata.header.machine == 40;
        const auto width = static_cast<std::uint8_t>(metadata.header.is_64 ? 8 : 4);
        const std::uint64_t limit = width == 4 ? UINT32_MAX : UINT64_MAX;
        const std::uint64_t ra = arm ? 14 : 1;
        const std::uint64_t sp = arm ? 13 : 2;
        elf_cfi_require(arm || !(metadata.header.flags & ~0x17u), ErrorCode::unsupported,
            "RISC-V embedded, ILP32-on-RV64 or unknown ELF ABI flags are unsupported for CFI");
        elf_cfi_require(fde.code_alignment != 0 && fde.size != 0, ErrorCode::malformed, "ELF CFI has an empty range or zero code alignment");
        elf_cfi_require(fde.begin.offset <= limit && fde.size - 1 <= limit - fde.begin.offset && pc.offset <= limit,
            ErrorCode::overflow, "ELF CFI range exceeds target address width");
        elf_cfi_require(fde.return_register == ra, ErrorCode::unsupported, "ELF CIE uses an unsupported return-address column");
        if (!arm) {
            const auto zero = context.find(0);
            elf_cfi_require(zero == context.end() || zero->second == 0, ErrorCode::malformed, "ELF CFI context has nonzero RISC-V x0");
        }
        const auto live = [&](std::uint64_t number) -> std::optional<std::uint64_t> {
            if (!arm && number == 0) return 0;
            const auto found = context.find(number);
            if (found == context.end()) return {};
            elf_cfi_require(found->second <= limit, ErrorCode::overflow, "ELF CFI register exceeds target width");
            return found->second;
        };
        ElfCfiState state, initial;
        std::size_t operations = 0;
        run_elf_integer_cfi(fde.cie_instructions, metadata.header.order, arm, fde.code_alignment,
            fde.data_alignment, limit, limit, state, initial, operations);
        initial = state;
        run_elf_integer_cfi(fde.instructions, metadata.header.order, arm, fde.code_alignment,
            fde.data_alignment, pc.offset - fde.begin.offset, limit, state, initial, operations);
        ElfUnwindResult result;
        if (state.cfa_expression) {
            result.cfa = evaluate_elf_cfi_expression(*state.cfa_expression, metadata.header.order, width,
                limit, context, read, {}, false, !arm, operations);
        } else {
            elf_cfi_require(state.cfa_register.has_value(), ErrorCode::unsupported,
                            "ELF CFI does not define an integer CFA rule");
            const auto base = live(*state.cfa_register);
            elf_cfi_require(base.has_value(), ErrorCode::out_of_bounds,
                            "ELF CFI CFA register is unavailable");
            result.cfa = elf_cfi_add(*base, state.cfa_offset, limit);
        }
        result.function = fde.begin;
        result.record_file_offset = fde.file_offset;
        result.source_kind = fde.source_kind;
        // Unspecified volatile registers are unavailable in the caller. ARM R9
        // is platform-defined; require an explicit CFI rule before exposing it.
        for (std::uint64_t number = 0; number <= (arm ? 15u : 31u); ++number) {
            const bool preserved = arm ? ((number >= 4 && number <= 8) || number == 10 || number == 11 || number == ra)
                : (number <= 4 || number == 8 || number == 9 || (number >= 18 && number <= 27));
            if (preserved) if (const auto value = live(number)) result.caller[number] = *value;
        }
        for (const auto &[number, rule] : state.rules) {
            if (!arm && number == 0) {
                elf_cfi_require(rule.kind == ElfCfiRule::Kind::same, ErrorCode::unsupported, "ELF CFI cannot redefine RISC-V x0");
                result.caller[0] = 0;
                continue;
            }
            if (rule.kind == ElfCfiRule::Kind::undefined) { result.caller.erase(number); continue; }
            if (rule.kind == ElfCfiRule::Kind::same || rule.kind == ElfCfiRule::Kind::reg) {
                const auto value = live(rule.kind == ElfCfiRule::Kind::same ? number : rule.source);
                elf_cfi_require(value.has_value(), ErrorCode::out_of_bounds, "ELF CFI register rule source is unavailable");
                result.caller[number] = *value;
                continue;
            }
            if (rule.kind == ElfCfiRule::Kind::expression ||
                rule.kind == ElfCfiRule::Kind::value_expression) {
                elf_cfi_require(rule.expression != nullptr, ErrorCode::malformed,
                                "ELF CFI expression rule has no expression block");
                const auto value = evaluate_elf_cfi_expression(*rule.expression, metadata.header.order, width,
                    limit, context, read, result.cfa, true, !arm, operations);
                if (rule.kind == ElfCfiRule::Kind::value_expression) {
                    result.caller[number] = value;
                } else {
                    elf_cfi_require(width - 1u <= limit - value, ErrorCode::overflow,
                                    "ELF CFI expression saved-register read exceeds target width");
                    elf_cfi_require(static_cast<bool>(read), ErrorCode::invalid_argument,
                                    "ELF CFI memory reader is empty");
                    const auto saved = read(value, width);
                    elf_cfi_require(saved.has_value(), ErrorCode::out_of_bounds,
                                    "ELF CFI expression saved-register word is unavailable");
                    elf_cfi_require(*saved <= limit, ErrorCode::overflow,
                                    "ELF CFI expression saved register exceeds target width");
                    result.caller[number] = *saved;
                }
                continue;
            }
            const auto value = elf_cfi_add(result.cfa, rule.offset, limit);
            if (rule.kind == ElfCfiRule::Kind::value_offset) { result.caller[number] = value; continue; }
            elf_cfi_require(width - 1u <= limit - value, ErrorCode::overflow, "ELF CFI stack read exceeds target width");
            elf_cfi_require(static_cast<bool>(read), ErrorCode::invalid_argument, "ELF CFI memory reader is empty");
            const auto saved = read(value, width);
            elf_cfi_require(saved.has_value(), ErrorCode::out_of_bounds, "ELF CFI saved-register word is unavailable");
            elf_cfi_require(*saved <= limit, ErrorCode::overflow, "ELF CFI saved register exceeds target width");
            result.caller[number] = *saved;
        }
        const auto return_address = result.caller.find(ra);
        elf_cfi_require(return_address != result.caller.end(), ErrorCode::out_of_bounds, "ELF CFI return address is unavailable");
        result.caller_pc = return_address->second;
        elf_cfi_require(arm ? ((result.caller_pc & 1) || !(result.caller_pc & 3)) : !(result.caller_pc & 1),
            ErrorCode::malformed, "ELF CFI return address has invalid instruction alignment");
        if (arm) result.caller[15] = result.caller_pc; // Retain the Thumb state bit in register state.
        if (state.rules.contains(sp)) {
            const auto restored_sp = result.caller.find(sp);
            elf_cfi_require(restored_sp != result.caller.end() && restored_sp->second == result.cfa,
                ErrorCode::unsupported, "ELF CFI stack-pointer rule disagrees with the caller CFA");
        }
        result.caller[sp] = result.cfa;
        return result;
    } catch (const ElfCfiFailure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ELF CFI evaluation state"};
    }
}
} // namespace
} // namespace hexlab
