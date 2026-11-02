#include "a64_internal.hpp"
namespace hexlab::a64_detail {
bool data(Instruction &i, std::uint32_t word) {
    const unsigned width = (word >> 31) ? 64 : 32;
    if ((word & 0x3b000000u) == 0x18000000u) {
        // Integer literal loads use the address of this instruction as PC,
        // with a signed imm19 scaled by four (no page alignment).
        const auto opc = word >> 30;
        if (word & 0x04000000u) {
            // AdvSIMD/FP literal loads use the same signed imm19 * 4
            // instruction-relative address as integer LDR literals. opc
            // selects S, D, or Q; the fourth encoding is reserved.
            if (opc == 3) return false;
            const unsigned data_width = opc == 0 ? 32u : opc == 1 ? 64u : 128u;
            const auto displacement = signed_value((word >> 5) & 0x7ffffu, 19) * 4;
            i.opcode = Opcode::a64_ldr;
            i.vector_bits = static_cast<std::uint16_t>(data_width);
            i.vector_element_bits = static_cast<std::uint16_t>(data_width);
            const RegisterOperand destination{RegisterBank::arm64_simd,
                static_cast<std::uint8_t>(word & 31), static_cast<std::uint16_t>(data_width), false};
            operand(i, destination, OperandAccess::write);
            // Narrow S/D literal loads clear the remaining bits of the
            // architectural V register. Publish that full write so generic
            // register consumers cannot preserve stale upper-lane facts.
            if (data_width < 128)
                i.register_writes.push_back({RegisterBank::arm64_simd,
                    static_cast<std::uint8_t>(word & 31), 128, false});
            MemoryOperand memory;
            memory.data_width = static_cast<std::uint16_t>(data_width);
            memory.address_width = 64;
            memory.ip_relative = true;
            memory.displacement = displacement;
            memory.resolved_address = target(i.address, displacement);
            operand(i, memory, OperandAccess::read);
            i.memory_read = true;
            return true;
        }
        if (opc == 3) return false; // PRFM literal is not an architectural data read.
        const bool signed_word = opc == 2;
        const unsigned data_width = signed_word ? 32 : opc == 1 ? 64 : 32;
        const auto displacement = signed_value((word >> 5) & 0x7ffffu, 19) * 4;
        i.opcode = signed_word ? Opcode::a64_ldrsw : Opcode::a64_ldr;
        operand(i, reg(word & 31, signed_word || data_width == 64 ? 64 : 32), OperandAccess::write);
        MemoryOperand memory;
        memory.data_width = static_cast<std::uint16_t>(data_width);
        memory.address_width = 64;
        memory.ip_relative = true;
        memory.displacement = displacement;
        memory.resolved_address = target(i.address, displacement);
        operand(i, memory, OperandAccess::read);
        i.memory_read = true;
    } else if ((word & 0x3ffffc00u) == 0x08dffc00u ||
               (word & 0x3ffffc00u) == 0x089ffc00u) {
        // Load-Acquire / Store-Release single-register forms. The size is
        // encoded independently of the fixed operation class: byte, halfword,
        // word, and doubleword transfers are all represented here.
        const bool load = (word & 0x00400000u) != 0;
        const unsigned size = word >> 30;
        const unsigned data_width = 8u << size;
        i.opcode = size == 0 ? (load ? Opcode::a64_ldrb : Opcode::a64_strb)
                  : size == 1 ? (load ? Opcode::a64_ldrh : Opcode::a64_strh)
                              : (load ? Opcode::a64_ldr : Opcode::a64_str);
        i.mnemonic_override = load ? (size == 0 ? "ldarb" : size == 1 ? "ldarh" : "ldar")
                                   : (size == 0 ? "stlrb" : size == 1 ? "stlrh" : "stlr");
        const auto data = reg(word & 31, size == 3 ? 64 : 32);
        operand(i, data, load ? OperandAccess::write : OperandAccess::read);
        MemoryOperand memory;
        memory.data_width = static_cast<std::uint16_t>(data_width);
        memory.address_width = 64;
        memory.base = reg((word >> 5) & 31, 64, true);
        i.register_reads.push_back(*memory.base);
        operand(i, memory, load ? OperandAccess::read : OperandAccess::write);
        i.memory_read = load;
        i.memory_write = !load;
        i.atomic_aq = load;
        i.atomic_rl = !load;
    } else if ((word & 0x3a000000u) == 0x28000000u && ((word >> 26) & 1u) == 0) {
        const auto opc = word >> 30;
        const auto mode = (word >> 23) & 3u;
        if ((opc != 0 && opc != 2) || mode == 0)
            return false; // Integer W/X offset, pre-index and post-index pairs only.
        const unsigned element_width = opc == 2 ? 64 : 32;
        const auto bytes = element_width / 8;
        const auto offset = signed_value((word >> 15) & 0x7f, 7) * static_cast<std::int64_t>(bytes);
        const bool load = ((word >> 22) & 1u) != 0;
        const bool post_index = mode == 1;
        const bool writeback = post_index || mode == 3;
        const auto base_index = (word >> 5) & 31;
        const auto first_index = word & 31;
        const auto second_index = (word >> 10) & 31;
        if (load && writeback && base_index != 31 && (base_index == first_index || base_index == second_index))
            return false; // Base/destination overlap has constrained-unpredictable writeback semantics.
        i.opcode = load ? Opcode::a64_ldp : Opcode::a64_stp;
        operand(i, reg(word & 31, element_width), load ? OperandAccess::write : OperandAccess::read);
        operand(i, reg((word >> 10) & 31, element_width), load ? OperandAccess::write : OperandAccess::read);
        MemoryOperand memory;
        memory.data_width = static_cast<std::uint16_t>(element_width);
        memory.address_width = 64;
        memory.base = reg(base_index, 64, true);
        memory.displacement = post_index ? 0 : offset;
        memory.writeback = writeback;
        memory.post_index = post_index;
        memory.writeback_displacement = offset;
        i.register_reads.push_back(*memory.base);
        if (writeback) i.register_writes.push_back(*memory.base);
        operand(i, memory, load ? OperandAccess::read : OperandAccess::write);
        i.memory_read = load;
        i.memory_write = !load;
    } else if ((word & 0x1f800000u) == 0x12800000u) {
        const auto op = (word >> 29) & 3, half = (word >> 21) & 3;
        if (op == 1 || (width == 32 && half >= 2))
            return false;
        i.opcode = op == 0 ? Opcode::a64_movn : op == 2 ? Opcode::a64_movz : Opcode::a64_movk;
        operand(i, reg(word & 31, width), op == 3 ? OperandAccess::read_write : OperandAccess::write);
        immediate(i, (word >> 5) & 0xffff, 16, width);
        if (half)
            immediate(i, half * 16, 2, 8);
    } else if ((word & 0x1f800000u) == 0x11000000u) {
        const bool subtract = (word & 0x40000000u) != 0, set_flags = (word & 0x20000000u) != 0;
        i.opcode = subtract ? (set_flags ? Opcode::a64_subs : Opcode::a64_sub)
                            : (set_flags ? Opcode::a64_adds : Opcode::a64_add);
        operand(i, reg(word & 31, width, !set_flags), OperandAccess::write);
        operand(i, reg((word >> 5) & 31, width, true), OperandAccess::read);
        immediate(i, static_cast<std::uint64_t>((word >> 10) & 0xfff) << ((word & 0x400000u) ? 12 : 0), 12, width);
        if (set_flags)
            i.register_writes.push_back(nzcv);
    } else if ((word & 0x1f000000u) == 0x10000000u) {
        const bool page = (word >> 31) != 0;
        const auto displacement =
            signed_value(((word >> 29) & 3) | (((word >> 5) & 0x7ffffu) << 2), 21) * (page ? 4096 : 1);
        const auto result =
            target({i.address.space, page ? i.address.offset & ~UINT64_C(4095) : i.address.offset}, displacement);
        i.opcode = page ? Opcode::a64_adrp : Opcode::a64_adr;
        operand(i, reg(word & 31), OperandAccess::write);
        MemoryOperand address;
        address.address_width = 64;
        address.ip_relative = true;
        address.displacement = displacement;
        address.resolved_address = result;
        operand(i, address, OperandAccess::address);
    } else if ((word & 0x3b200c00u) == 0x38200800u) {
        const auto size = word >> 30, op = (word >> 22) & 3;
        const auto option = (word >> 13) & 7;
        const bool signed_narrow = size < 2 && op >= 2;
        const bool signed_word = size == 2 && op == 2;
        if ((!signed_narrow && !signed_word && (op > 1 || size == 2)) ||
            (option != 2 && option != 3 && option != 6 && option != 7))
            return false;
        const bool load = op != 0;
        i.opcode = signed_narrow ? (size == 0 ? Opcode::a64_ldrsb : Opcode::a64_ldrsh)
                   : signed_word ? Opcode::a64_ldrsw
                   : size == 0   ? (load ? Opcode::a64_ldrb : Opcode::a64_strb)
                   : size == 1 ? (load ? Opcode::a64_ldrh : Opcode::a64_strh)
                               : (load ? Opcode::a64_ldr : Opcode::a64_str);
        const auto destination_width = signed_word || size == 3 || (signed_narrow && op == 2) ? 64u : 32u;
        operand(i, reg(word & 31, destination_width), load ? OperandAccess::write : OperandAccess::read);
        MemoryOperand memory;
        memory.data_width = signed_word ? 32 : static_cast<std::uint16_t>(8u << size);
        memory.address_width = 64;
        memory.base = reg((word >> 5) & 31, 64, true);
        const bool word_index = option == 2 || option == 6;
        memory.index = reg((word >> 16) & 31, word_index ? 32 : 64);
        memory.index_extend = option == 2 ? "uxtw" : option == 6 ? "sxtw" : option == 7 ? "sxtx" : "";
        memory.index_shift_amount = (word & 0x1000u) ? static_cast<std::uint8_t>(size) : 0;
        i.register_reads.push_back(*memory.base);
        i.register_reads.push_back(*memory.index);
        operand(i, memory, load ? OperandAccess::read : OperandAccess::write);
        i.memory_read = load;
        i.memory_write = !load;
    } else if ((word & 0x3b200000u) == 0x38000000u) {
        const auto size = word >> 30, op = (word >> 22) & 3;
        const auto mode = (word >> 10) & 3;
        const bool signed_narrow = size < 2 && op >= 2;
        const bool signed_word = size == 2 && op == 2;
        if ((!signed_narrow && !signed_word && op > 1) || mode == 2)
            return false; // Unprivileged and prefetch forms remain outside this slice.
        const bool load = op != 0, writeback = mode != 0, post_index = mode == 1;
        const auto data_register = word & 31, base_register = (word >> 5) & 31;
        if (writeback && base_register != 31 && base_register == data_register)
            return false; // Writeback overlap has constrained-unpredictable semantics.
        const auto offset = signed_value((word >> 12) & 0x1ff, 9);
        i.opcode = signed_narrow ? (size == 0 ? Opcode::a64_ldrsb : Opcode::a64_ldrsh)
                   : signed_word ? Opcode::a64_ldrsw
                   : size == 0   ? (load ? Opcode::a64_ldrb : Opcode::a64_strb)
                   : size == 1 ? (load ? Opcode::a64_ldrh : Opcode::a64_strh)
                               : (load ? Opcode::a64_ldr : Opcode::a64_str);
        const auto destination_width = signed_word || size == 3 || (signed_narrow && op == 2) ? 64u : 32u;
        operand(i, reg(data_register, destination_width), load ? OperandAccess::write : OperandAccess::read);
        MemoryOperand memory;
        memory.data_width = signed_word ? 32 : static_cast<std::uint16_t>(8u << size);
        memory.address_width = 64;
        memory.base = reg(base_register, 64, true);
        memory.displacement = post_index ? 0 : offset;
        memory.writeback = writeback;
        memory.post_index = post_index;
        memory.writeback_displacement = writeback ? offset : 0;
        i.register_reads.push_back(*memory.base);
        if (writeback) i.register_writes.push_back(*memory.base);
        operand(i, memory, load ? OperandAccess::read : OperandAccess::write);
        i.memory_read = load;
        i.memory_write = !load;
    } else if ((word & 0x3f000000u) == 0x39000000u) {
        const auto size = word >> 30, op = (word >> 22) & 3;
        const bool signed_narrow = size < 2 && op >= 2;
        const bool signed_word = size == 2 && op == 2;
        if ((!signed_narrow && !signed_word && op > 1))
            return false; // Prefetch and reserved forms remain outside this slice.
        const bool load = op != 0;
        i.opcode = signed_narrow ? (size == 0 ? Opcode::a64_ldrsb : Opcode::a64_ldrsh)
                   : signed_word ? Opcode::a64_ldrsw
                   : size == 0   ? (load ? Opcode::a64_ldrb : Opcode::a64_strb)
                   : size == 1 ? (load ? Opcode::a64_ldrh : Opcode::a64_strh)
                               : (load ? Opcode::a64_ldr : Opcode::a64_str);
        const auto destination_width = signed_word || size == 3 || (signed_narrow && op == 2) ? 64u : 32u;
        operand(i, reg(word & 31, destination_width), load ? OperandAccess::write : OperandAccess::read);
        MemoryOperand memory;
        memory.data_width = signed_word ? 32 : static_cast<std::uint16_t>(8u << size);
        memory.address_width = 64;
        memory.base = reg((word >> 5) & 31, 64, true);
        memory.displacement = static_cast<std::int64_t>(((word >> 10) & 0xfff) << size);
        i.register_reads.push_back(*memory.base);
        operand(i, memory, load ? OperandAccess::read : OperandAccess::write);
        i.memory_read = load;
        i.memory_write = !load;
    } else {
        return false;
    }
    return true;
}
} // namespace hexlab::a64_detail
