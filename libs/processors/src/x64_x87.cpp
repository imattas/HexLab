#include "x64_internal.hpp"
#include <algorithm>

namespace hexlab::x64_detail {
namespace {
constexpr std::uint16_t x87_width = 80;
std::uint16_t x87_operand_width(const State &s) {
    return s.rules.operand_width(s.operand_override, 0);
}
RegisterOperand st(unsigned index) {
    return {RegisterBank::x87, static_cast<std::uint8_t>(index), x87_width, false};
}
RegisterOperand status() { return {RegisterBank::x87_status, 0, 16, false}; }
RegisterOperand control() { return {RegisterBank::x87_control, 0, 16, false}; }
RegisterOperand tag() { return {RegisterBank::x87_tag, 0, 16, false}; }
void add_register(std::vector<RegisterOperand> &registers, RegisterOperand value) {
    if (std::find(registers.begin(), registers.end(), value) == registers.end()) registers.push_back(value);
}
void status_read_write(State &s) {
    add_register(s.i.register_reads, status());
    add_register(s.i.register_writes, status());
}
void environment_write(State &s) {
    add_register(s.i.register_writes, status());
    add_register(s.i.register_writes, control());
    add_register(s.i.register_writes, tag());
}
void environment_read(State &s) {
    add_register(s.i.register_reads, status());
    add_register(s.i.register_reads, control());
    add_register(s.i.register_reads, tag());
}
void mnemonic(State &s, const char *name) {
    s.i.opcode = Opcode::x87;
    s.i.mnemonic_override = name;
}
void push(State &s) {
    add_register(s.i.register_writes, st(0));
    status_read_write(s);
    add_register(s.i.register_reads, tag());
    add_register(s.i.register_writes, tag());
    ++s.i.x87_stack_delta;
}
void pop(State &s) {
    add_register(s.i.register_writes, st(0));
    status_read_write(s);
    add_register(s.i.register_reads, tag());
    add_register(s.i.register_writes, tag());
    --s.i.x87_stack_delta;
}
void compare_status(State &s) { status_read_write(s); }
void arithmetic_environment(State &s) {
    // x87 arithmetic reads PC/RC from the control word and updates sticky
    // exception/status bits, including C1. Keep those dependencies visible
    // to data-flow analysis even when the rounded value is not modeled.
    add_register(s.i.register_reads, control());
    status_read_write(s);
}
void free_tag(State &s) {
    add_register(s.i.register_reads, tag());
    add_register(s.i.register_writes, tag());
}
void binary(State &s, const char *name, unsigned destination, unsigned source, bool pop_result = false) {
    mnemonic(s, name);
    const auto d = st(destination), r = st(source);
    s.operand(d, OperandAccess::read_write);
    s.operand(r, OperandAccess::read);
    arithmetic_environment(s);
    if (pop_result)
        pop(s);
}
const char *arithmetic_name(unsigned group) {
    constexpr const char *names[]{"fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr", "fdiv", "fdivr"};
    return names[group & 7];
}
const char *integer_arithmetic_name(unsigned group) {
    constexpr const char *names[]{"fiadd", "fimul", "ficom", "ficomp", "fisub", "fisubr", "fidiv", "fidivr"};
    return names[group & 7];
}
bool memory_form(State &s, std::uint8_t opcode, unsigned group, Operand &rm) {
    auto *mem = std::get_if<MemoryOperand>(&rm);
    if (!mem)
        return false;
    const char *name = nullptr;
    unsigned width = 0;
    OperandAccess access = OperandAccess::read;
    switch (opcode) {
    case 0xd8: // m32real arithmetic
        width = 32;
        name = arithmetic_name(group);
        access = (group == 2 || group == 3) ? OperandAccess::read : OperandAccess::read;
        break;
    case 0xd9:
        switch (group) {
        case 0: name = "fld"; width = 32; break;
        case 2: name = "fst"; width = 32; access = OperandAccess::write; break;
        case 3: name = "fstp"; width = 32; access = OperandAccess::write; break;
        case 4: name = "fldenv"; width = x87_operand_width(s) == 16 ? 112 : 224; break;
        case 5: name = "fldcw"; width = 16; break;
        case 6: name = "fnstenv"; width = x87_operand_width(s) == 16 ? 112 : 224; access = OperandAccess::write; break;
        case 7: name = "fnstcw"; width = 16; access = OperandAccess::write; break;
        default: invalid("Reserved D9 x87 memory extension");
        }
        break;
    case 0xda: // m32int arithmetic
        width = 32;
        name = integer_arithmetic_name(group);
        break;
    case 0xdb:
        switch (group) {
        case 0: name = "fild"; width = 32; break;
        case 1: name = "fisttp"; width = 32; access = OperandAccess::write; break;
        case 2: name = "fist"; width = 32; access = OperandAccess::write; break;
        case 3: name = "fistp"; width = 32; access = OperandAccess::write; break;
        case 5: name = "fld"; width = 80; break;
        case 7: name = "fstp"; width = 80; access = OperandAccess::write; break;
        default: invalid("Reserved DB x87 memory extension");
        }
        break;
    case 0xdc: // m64real arithmetic
        width = 64;
        name = arithmetic_name(group);
        break;
    case 0xdd:
        switch (group) {
        case 0: name = "fld"; width = 64; break;
        case 1: name = "fisttp"; width = 64; access = OperandAccess::write; break;
        case 2: name = "fst"; width = 64; access = OperandAccess::write; break;
        case 3: name = "fstp"; width = 64; access = OperandAccess::write; break;
        case 4: name = "frstor"; width = x87_operand_width(s) == 16 ? 752 : 864; break;
        case 6: name = "fnsave"; width = x87_operand_width(s) == 16 ? 752 : 864; access = OperandAccess::write; break;
        case 7: name = "fnstsw"; width = 16; access = OperandAccess::write; break;
        default: invalid("Reserved DD x87 memory extension");
        }
        break;
    case 0xde: // m16int arithmetic
        width = 16;
        name = integer_arithmetic_name(group);
        break;
    case 0xdf:
        switch (group) {
        case 0: name = "fild"; width = 16; break;
        case 1: name = "fisttp"; width = 16; access = OperandAccess::write; break;
        case 2: name = "fist"; width = 16; access = OperandAccess::write; break;
        case 3: name = "fistp"; width = 16; access = OperandAccess::write; break;
        case 4: name = "fbld"; width = 80; break;
        case 5: name = "fild"; width = 64; break;
        case 6: name = "fbstp"; width = 80; access = OperandAccess::write; break;
        case 7: name = "fistp"; width = 64; access = OperandAccess::write; break;
        }
        break;
    default: return false;
    }
    mem->data_width = static_cast<std::uint16_t>(width);
    mnemonic(s, name);
    s.operand(*mem, access);
    const bool arithmetic = opcode == 0xd8 || opcode == 0xda || opcode == 0xdc || opcode == 0xde;
    const bool stores_st0 = (opcode == 0xd9 && (group == 2 || group == 3)) ||
                            (opcode == 0xdb && (group == 1 || group == 2 || group == 3 || group == 7)) ||
                            (opcode == 0xdd && (group == 1 || group == 2 || group == 3)) ||
                            (opcode == 0xdf && (group == 1 || group == 2 || group == 3 || group == 6 || group == 7));
    if (arithmetic || stores_st0)
        s.i.register_reads.push_back(st(0));
    if (arithmetic && (group == 2 || group == 3)) compare_status(s);
    if (arithmetic && group != 2 && group != 3) {
        arithmetic_environment(s);
        s.i.register_writes.push_back(st(0));
    }
    if (opcode == 0xd9 && group == 5) s.i.register_writes.push_back(control());
    if (opcode == 0xd9 && group == 7) s.i.register_reads.push_back(control());
    if (opcode == 0xdd && group == 7) s.i.register_reads.push_back(status());
    if (opcode == 0xd9 && group == 4) environment_write(s);
    if (opcode == 0xd9 && group == 6) {
        environment_read(s);
        s.i.register_writes.push_back(control()); // FNSTENV masks x87 exceptions after saving the environment.
    }
    if (opcode == 0xdd && group == 4) environment_write(s);
    if (opcode == 0xdd && group == 6) {
        environment_read(s);
        environment_write(s); // FNSAVE stores then initializes the x87 environment.
    }
    if ((opcode == 0xd9 && group == 0) || (opcode == 0xdb && (group == 0 || group == 5)) ||
        (opcode == 0xdd && group == 0) || (opcode == 0xdf && (group == 0 || group == 4 || group == 5)))
        push(s);
    else if ((opcode == 0xd9 && group == 3) || (opcode == 0xdb && (group == 1 || group == 3 || group == 7)) ||
             (opcode == 0xdd && group == 3) ||
             (opcode == 0xdf && (group == 1 || group == 3 || group == 6 || group == 7)))
        pop(s);
    else if (arithmetic && group == 3)
        pop(s);
    if (opcode == 0xdd && group == 4)
        for (unsigned n = 0; n < 8; ++n) s.i.register_writes.push_back(st(n));
    if (opcode == 0xdd && group == 6) {
        for (unsigned n = 0; n < 8; ++n) {
            s.i.register_reads.push_back(st(n));
            s.i.register_writes.push_back(st(n));
        }
    }
    return true;
}
bool register_form(State &s, std::uint8_t opcode, unsigned group, unsigned index) {
    const auto st0 = st(0), sti = st(index);
    if (opcode == 0xd8) {
        switch (group) {
        case 0: binary(s, "fadd", 0, index); return true;
        case 1: binary(s, "fmul", 0, index); return true;
        case 2:
            mnemonic(s, "fcom"); s.operand(sti, OperandAccess::read); s.i.register_reads.push_back(st0);
            compare_status(s); return true;
        case 3:
            mnemonic(s, "fcomp"); s.operand(sti, OperandAccess::read); s.i.register_reads.push_back(st0);
            compare_status(s); pop(s); return true;
        case 4: binary(s, "fsub", 0, index); return true;
        case 5: binary(s, "fsubr", 0, index); return true;
        case 6: binary(s, "fdiv", 0, index); return true;
        case 7: binary(s, "fdivr", 0, index); return true;
        }
    }
    if (opcode == 0xd9) {
        if (group == 0) {
            mnemonic(s, "fld"); s.operand(sti, OperandAccess::read); push(s); return true;
        }
        if (group == 1) {
            mnemonic(s, "fxch"); s.operand(sti, OperandAccess::read_write);
            s.i.register_reads.push_back(st0); s.i.register_writes.push_back(st0); return true;
        }
        if (group == 2 && index == 0) { mnemonic(s, "fnop"); return true; }
        if (group == 4) {
            static constexpr const char *names[]{"fchs", "fabs", nullptr, nullptr, "ftst", "fxam", nullptr, nullptr};
            if (names[index]) {
                mnemonic(s, names[index]);
                if (index == 0 || index == 1) {
                    s.i.register_reads.push_back(st0); s.i.register_writes.push_back(st0);
                } else if (index == 4 || index == 5) {
                    s.i.register_reads.push_back(st0);
                    status_read_write(s);
                }
                return true;
            }
            invalid("Reserved D9 unary register encoding");
        }
        if (group == 5) {
            static constexpr const char *names[]{"fld1", "fldl2t", "fldl2e", "fldpi", "fldlg2", "fldln2", "fldz", nullptr};
            if (!names[index]) invalid("Reserved D9 constant encoding");
            mnemonic(s, names[index]); push(s); return true;
        }
        if (group == 6 || group == 7) {
            // D9 F6/F7 are FDECSTP/FINCSTP; F0..F5 and F8..FF use
            // separate architectural sub-tables.
            const auto low = index;
            const char *name = nullptr;
            if (group == 6) {
                constexpr const char *g6[]{"f2xm1", "fyl2x", "fptan", "fpatan", "fxtract", "fprem1", "fdecstp", "fincstp"};
                name = g6[low];
            } else {
                constexpr const char *g7[]{"fprem", "fyl2xp1", "fsqrt", "fsincos", "frndint", "fscale", "fsin", "fcos"};
                name = g7[low];
            }
            mnemonic(s, name);
            if (index <= 5) {
                s.i.register_reads.push_back(st0);
                s.i.register_writes.push_back(st0);
                const bool uses_st1 = group == 6 ? index == 1 || index == 3 || index == 5
                                                 : index == 0 || index == 1 || index == 5;
                if (uses_st1)
                    s.i.register_reads.push_back(st(1));
                if ((group == 6 && (index == 1 || index == 3)) || (group == 7 && index == 1))
                    s.i.register_writes.push_back(st(1));
                if ((group == 6 && (index == 1 || index == 3)) || (group == 7 && index == 1))
                    pop(s);
                if ((group == 6 && (index == 2 || index == 4)) || (group == 7 && index == 3))
                    push(s);
                // The transcendental, remainder, scaling, and rounding
                // operations can consult the control word and update sticky
                // exception/status bits. Stack effects above are separate:
                // they describe only the normal result stack movement.
                arithmetic_environment(s);
            }
            if (group == 6 && (index == 6 || index == 7)) status_read_write(s);
            return true;
        }
    }
    if (opcode == 0xda && (group == 0 || group == 1 || group == 2 || group == 3)) {
        static constexpr const char *names[]{"fcmovb", "fcmove", "fcmovbe", "fcmovu"};
        mnemonic(s, names[group]); s.operand(st0, OperandAccess::read_write); s.operand(sti, OperandAccess::read);
        s.flags_read = true; return true;
    }
    if (opcode == 0xda && group == 5 && index == 1) {
        mnemonic(s, "fucompp"); s.i.register_reads.push_back(st0); s.i.register_reads.push_back(st(1));
        compare_status(s); pop(s); pop(s); return true;
    }
    if (opcode == 0xdb && (group <= 3)) {
        static constexpr const char *names[]{"fcmovnb", "fcmovne", "fcmovnbe", "fcmovnu"};
        mnemonic(s, names[group]); s.operand(st0, OperandAccess::read_write); s.operand(sti, OperandAccess::read);
        s.flags_read = true; return true;
    }
    if (opcode == 0xdb && group == 4 && index <= 4) {
        static constexpr const char *names[]{"fneni", "fndisi", "fnclex", "fninit", "fsetpm"};
        mnemonic(s, names[index]);
        if (index == 2) s.i.register_writes.push_back(status());
        if (index == 3) {
            s.i.register_writes.push_back(status());
            s.i.register_writes.push_back(control());
            s.i.register_writes.push_back(tag());
            for (unsigned n = 0; n < 8; ++n) s.i.register_writes.push_back(st(n));
        }
        return true;
    }
    if (opcode == 0xdb && (group == 5 || group == 6)) {
        mnemonic(s, group == 5 ? "fucomi" : "fcomi");
        s.operand(st0, OperandAccess::read); s.operand(sti, OperandAccess::read);
        s.flags_write = true; compare_status(s); return true;
    }
    if (opcode == 0xda || opcode == 0xdb)
        invalid("Reserved x87 register encoding");
    if (opcode == 0xdc) {
        if (group == 0 || group == 1 || group == 4 || group == 5 || group == 6 || group == 7) {
            const char *name = arithmetic_name(group);
            // DC encodes destination ST(i), source ST(0), with the subtraction
            // and division direction bits exchanged relative to D8.
            if (group == 5) name = "fsub";
            if (group == 4) name = "fsubr";
            if (group == 7) name = "fdiv";
            if (group == 6) name = "fdivr";
            binary(s, name, index, 0); return true;
        }
        invalid("Reserved DC register extension");
    }
    if (opcode == 0xdd) {
        if (group == 0) {
            mnemonic(s, "ffree"); s.operand(sti, OperandAccess::write); free_tag(s); return true;
        }
        if (group == 2 || group == 3) {
            mnemonic(s, group == 2 ? "fst" : "fstp");
            s.operand(sti, OperandAccess::write); s.i.register_reads.push_back(st0);
            if (group == 3) pop(s); return true;
        }
        if (group == 4 || group == 5) {
            mnemonic(s, group == 4 ? "fucom" : "fucomp"); s.operand(sti, OperandAccess::read);
            s.i.register_reads.push_back(st0);
            compare_status(s);
            if (group == 5) pop(s); return true;
        }
        invalid("Reserved DD register extension");
    }
    if (opcode == 0xde) {
        if (group == 0 || group == 1 || group == 4 || group == 5 || group == 6 || group == 7) {
            const char *name = arithmetic_name(group);
            if (group == 4) name = "fsubrp";
            if (group == 5) name = "fsubp";
            if (group == 6) name = "fdivrp";
            if (group == 7) name = "fdivp";
            if (index == 0 && group == 1) { // FCOMP ST(0) is encoded as DE D9 below.
                binary(s, name, 0, index, true); return true;
            }
            binary(s, name, index, 0, true); return true;
        }
        if (group == 3 && index == 1) {
            mnemonic(s, "fcompp"); s.i.register_reads.push_back(st0); s.i.register_reads.push_back(st(1));
            compare_status(s); pop(s); pop(s); return true;
        }
        invalid("Reserved DE register extension");
    }
    if (opcode == 0xdf) {
        if (group == 0) { mnemonic(s, "ffreep"); s.operand(sti, OperandAccess::write); free_tag(s); pop(s); return true; }
        if (group == 4 && index == 0) {
            mnemonic(s, "fnstsw"); s.operand(RegisterOperand{RegisterBank::gpr, 0, 16, false}, OperandAccess::write);
            s.i.register_reads.push_back(status()); return true;
        }
        if (group == 5 || group == 6) {
            mnemonic(s, group == 5 ? "fucomip" : "fcomip");
            s.operand(st0, OperandAccess::read); s.operand(sti, OperandAccess::read);
            s.flags_write = true; compare_status(s); pop(s); return true;
        }
        invalid("Reserved DF register extension");
    }
    invalid("Reserved x87 register encoding");
}
} // namespace

bool x87(State &s, std::uint8_t opcode) {
    if (opcode < 0xd8 || opcode > 0xdf)
        return false;
    // Decode the full ModRM once. Memory widths are assigned after classifying
    // the escape and extension, while the common decoder supplies all address
    // and displacement details.
    auto parsed = modrm(s, 32);
    if (parsed.mod != 3)
        return memory_form(s, opcode, parsed.group, parsed.rm);
    const auto register_index = std::get<RegisterOperand>(parsed.rm).index & 7;
    if (opcode == 0xde && parsed.group == 3 && register_index == 1) {
        mnemonic(s, "fcompp"); s.operand(st(0), OperandAccess::read); s.operand(st(1), OperandAccess::read);
        compare_status(s); pop(s); pop(s); return true;
    }
    return register_form(s, opcode, parsed.group, register_index);
}
} // namespace hexlab::x64_detail
