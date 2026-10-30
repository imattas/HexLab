#include "hexlab/loaders/elf_unwind.hpp"
#include "hexlab/loaders/macho_unwind.hpp"
#include "elf_cfi_arm_riscv.hpp"

namespace hexlab {
namespace {
std::optional<MachOUnwindRegister> cfi_register(bool arm64, std::uint64_t reg) {
    if (arm64) {
        if (reg >= 19 && reg <= 30)
            return static_cast<MachOUnwindRegister>(static_cast<unsigned>(MachOUnwindRegister::arm64_x19) +
                                                    static_cast<unsigned>(reg - 19));
        if (reg >= 72 && reg <= 79)
            return static_cast<MachOUnwindRegister>(static_cast<unsigned>(MachOUnwindRegister::arm64_d8) +
                                                    static_cast<unsigned>(reg - 72));
        if (reg == 31) return MachOUnwindRegister::arm64_sp;
        return std::nullopt;
    }
    switch (reg) {
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
std::uint64_t dwarf_register(bool arm64, MachOUnwindRegister reg) {
    if (arm64) {
        const auto value = static_cast<unsigned>(reg);
        const auto first_x = static_cast<unsigned>(MachOUnwindRegister::arm64_x19);
        const auto first_d = static_cast<unsigned>(MachOUnwindRegister::arm64_d8);
        if (value >= first_x && value <= static_cast<unsigned>(MachOUnwindRegister::arm64_x30))
            return 19 + value - first_x;
        if (value >= first_d && value <= static_cast<unsigned>(MachOUnwindRegister::arm64_d15))
            return 72 + value - first_d;
        if (reg == MachOUnwindRegister::arm64_sp) return 31;
        if (reg == MachOUnwindRegister::arm64_pc) return 32;
        return UINT64_MAX;
    }
    switch (reg) {
    case MachOUnwindRegister::x86_64_rbp: return 6;
    case MachOUnwindRegister::x86_64_rsp: return 7;
    case MachOUnwindRegister::x86_64_rip: return 16;
    case MachOUnwindRegister::x86_64_rbx: return 3;
    case MachOUnwindRegister::x86_64_r12: return 12;
    case MachOUnwindRegister::x86_64_r13: return 13;
    case MachOUnwindRegister::x86_64_r14: return 14;
    case MachOUnwindRegister::x86_64_r15: return 15;
    default: return UINT64_MAX;
    }
}
}

Result<ElfUnwindResult> evaluate_elf_unwind(const ElfMetadata &metadata, Address pc,
                                             const ElfUnwindContext &context,
                                             const ElfUnwindMemoryReader &read,
                                             ElfMipsInstructionMode mips_mode) {
    const bool arm64 = metadata.header.machine == 183 && metadata.header.is_64;
    const bool x86_64 = metadata.header.machine == 62 && metadata.header.is_64;
    const bool arm = metadata.header.machine == 40 && !metadata.header.is_64;
    const bool mips32 = metadata.header.machine == 8 && !metadata.header.is_64;
    const bool riscv = metadata.header.machine == 243;
    if (!arm64 && !x86_64 && !arm && !mips32 && !riscv)
        return Error{ErrorCode::unsupported, "ELF live CFI requires x86-64, AArch64, ARM32, MIPS32 or RV32/RV64"};
    if (arm) pc.offset &= ~UINT64_C(1);
    // The legacy Mach-O bridge decodes fixed CFI operands as little-endian.
    // Do not silently interpret a big-endian AArch64 recipe through that path.
    if ((arm64 || x86_64) && metadata.header.order != ByteOrder::little)
        return Error{ErrorCode::unsupported, "64-bit ELF CFI bridge requires little-endian instruction operands"};
    const ElfEhFrameFunction *match = nullptr;
    for (const auto source : {ElfCfiSectionKind::eh_frame, ElfCfiSectionKind::debug_frame}) {
        for (const auto &fde : metadata.eh_frame_functions) {
            if (fde.source_kind != source || fde.begin.space != pc.space || pc.offset < fde.begin.offset ||
                pc.offset - fde.begin.offset >= fde.size) continue;
            if (match) return Error{ErrorCode::malformed, "Overlapping ELF FDEs in the selected CFI source cover PC"};
            match = &fde;
        }
        if (match) break;
    }
    if (!match) return Error{ErrorCode::out_of_bounds, "No ELF .eh_frame or .debug_frame FDE covers PC"};
    constexpr std::size_t max_cfi_program_bytes = 1024 * 1024;
    if (match->cie_instructions.size() > max_cfi_program_bytes ||
        match->instructions.size() > max_cfi_program_bytes - match->cie_instructions.size())
        return Error{ErrorCode::resource_limit, "Combined ELF CIE/FDE program exceeds the 1 MiB evaluation limit"};
    if (arm || mips32 || riscv)
        return evaluate_elf_integer_unwind(metadata, *match, pc, context, read,
            mips32 && mips_mode != ElfMipsInstructionMode::classic);

    MachOMetadata bridge;
    MachOSlice slice;
    slice.header.cpu_type = arm64 ? 0x0100000cu : 0x01000007u;
    bridge.container.slices.push_back(std::move(slice));
    MachOEhFrameFunction fde;
    fde.section = match->section;
    fde.record_file_offset = match->file_offset;
    fde.size = match->size;
    fde.address = match->begin;
    fde.code_alignment = match->code_alignment;
    fde.data_alignment = match->data_alignment;
    fde.return_register = match->return_register;
    fde.cie_instructions = match->cie_instructions;
    fde.instructions = match->instructions;
    bridge.eh_frame_functions.push_back(std::move(fde));

    MachOUnwindContext registers;
    for (const auto &[number, value] : context) {
        const auto target = cfi_register(arm64, number);
        if (target) registers[*target] = value;
    }
    auto outcome = evaluate_macho_unwind(bridge, pc, registers, read);
    if (!outcome) return outcome.error();
    ElfUnwindResult result;
    result.cfa = outcome.value().cfa;
    result.function = outcome.value().function;
    result.record_file_offset = outcome.value().record_file_offset;
    result.source_kind = match->source_kind;
    for (const auto &[reg, value] : outcome.value().caller) {
        const auto number = dwarf_register(arm64, reg);
        if (number != UINT64_MAX) result.caller[number] = value;
    }
    if (const auto caller_pc = result.caller.find(arm64 ? 32 : 16); caller_pc != result.caller.end())
        result.caller_pc = caller_pc->second;
    return result;
}
} // namespace hexlab
