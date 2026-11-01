#include "x64_internal.hpp"

namespace hexlab::x64_detail {
bool decimal_adjust(State &s, std::uint8_t opcode, bool extended) {
    if (extended || (opcode != 0x27 && opcode != 0x2f && opcode != 0x37 && opcode != 0x3f))
        return false;
    if (s.rules.long_mode())
        invalid("Decimal-adjust instructions are not valid in long mode");
    if (s.group1 == 0xf0)
        invalid("LOCK is not valid for decimal adjustment");
    if (s.group1 != 0)
        unsupported("Repeat prefixes on decimal adjustment are outside the typed subset");
    const bool unpacked = opcode == 0x37 || opcode == 0x3f;
    s.i.opcode = opcode == 0x27 ? Opcode::daa : opcode == 0x2f ? Opcode::das :
                 opcode == 0x37 ? Opcode::aaa : Opcode::aas;
    const RegisterOperand al{RegisterBank::gpr, 0, 8, false};
    s.i.register_reads.push_back(al);
    s.i.register_writes.push_back(al);
    if (unpacked) {
        const RegisterOperand ah{RegisterBank::gpr, 0, 8, true};
        s.i.register_reads.push_back(ah);
        s.i.register_writes.push_back(ah);
    }
    s.flags_read = true;
    s.flags_write = true;
    s.flags_read_mask = unpacked ? UINT64_C(0x10) : UINT64_C(0x11);
    // All six arithmetic flags are replaced: some become undefined, rather
    // than preserving their old value. Evaluators report definedness separately.
    s.flags_write_mask = UINT64_C(0x8d5);
    return true;
}
} // namespace hexlab::x64_detail
