#pragma once

#include "hexlab/image/elf_metadata.hpp"
#include "hexlab/loaders/loaders_export.hpp"
#include <functional>
#include <map>
#include <optional>

namespace hexlab {

using ElfUnwindContext = std::map<std::uint64_t, std::uint64_t>; // DWARF register number -> value
// The reader returns a scalar decoded in the ELF target's byte order.
using ElfUnwindMemoryReader = std::function<std::optional<std::uint64_t>(std::uint64_t, std::uint8_t)>;

struct ElfUnwindResult {
    ElfUnwindContext caller;
    std::uint64_t cfa = 0;
    Address function;
    std::uint64_t record_file_offset = 0;
    // Kept separate because RISC-V has no DWARF PC register column (32 is F0).
    // ARM retains the raw return address including the Thumb state bit.
    std::uint64_t caller_pc = 0;
    ElfCfiSectionKind source_kind = ElfCfiSectionKind::eh_frame;
};

// Evaluate a validated x86-64, AArch64, ARM32/Thumb or RV32/RV64 FDE.
// ARM/RISC-V support bounded integer CFA/register rules; expressions and other
// register banks fail explicitly. Stack words use the ELF address width; the
// callback returns words decoded in target byte order. PC is a link-time code
// address (ARM state bit is ignored for lookup). See docs/elf-dwarf-unwind.md.
// Prefer .eh_frame; use .debug_frame only when no accepted .eh_frame FDE covers
// the PC. Overlapping FDEs within the selected source kind fail explicitly.
HEXLAB_LOADERS_EXPORT Result<ElfUnwindResult> evaluate_elf_unwind(
    const ElfMetadata &, Address pc, const ElfUnwindContext &, const ElfUnwindMemoryReader &);

} // namespace hexlab
