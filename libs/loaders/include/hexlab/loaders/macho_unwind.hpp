#pragma once
#include "hexlab/image/macho_metadata.hpp"
#include "hexlab/loaders/loaders_export.hpp"
#include <cstdint>
#include <functional>
#include <map>
#include <optional>

namespace hexlab {

enum class MachOUnwindRegister {
    x86_64_rbp, x86_64_rsp, x86_64_rip, x86_64_rbx, x86_64_r12, x86_64_r13,
    x86_64_r14, x86_64_r15,
    arm64_x19, arm64_x20, arm64_x21, arm64_x22, arm64_x23, arm64_x24,
    arm64_x25, arm64_x26, arm64_x27, arm64_x28, arm64_x29, arm64_x30,
    arm64_d8, arm64_d9, arm64_d10, arm64_d11, arm64_d12, arm64_d13, arm64_d14, arm64_d15,
    arm64_sp, arm64_pc
};

using MachOUnwindContext = std::map<MachOUnwindRegister, std::uint64_t>;
using MachOUnwindMemoryReader = std::function<std::optional<std::uint64_t>(std::uint64_t, std::uint8_t)>;

struct MachOUnwindResult {
    MachOUnwindContext caller;
    std::uint64_t cfa = 0;
    Address function;
    std::uint32_t encoding = 0;
    std::uint64_t record_file_offset = 0;
    std::uint32_t expression_rules_evaluated = 0;
    // AArch64 CFI can identify a signed return address. The evaluator reports
    // this state without attempting pointer authentication.
    bool return_address_signed = false;
    // GNU CFI reports the outgoing-argument stack size at this PC. It is
    // exposed as metadata and does not alter the recovered caller context.
    std::optional<std::uint64_t> gnu_args_size;
    bool operator==(const MachOUnwindResult &) const = default;
};

// Evaluates a bounded eh_frame FDE containing PC, or falls back to a compact-
// unwind entry when no FDE covers it. Arm64 DWARF-mode compact entries bind
// their exact FDE offset before the generic range lookup. Unsupported recipes
// are reported explicitly; the callback is asked for 8-byte stack words,
// 1..8-byte DWARF dereferences, or a bounded 7-byte x86_64 indirect-stack read.
HEXLAB_LOADERS_EXPORT Result<MachOUnwindResult> evaluate_macho_unwind(
    const MachOMetadata &, Address pc, const MachOUnwindContext &, const MachOUnwindMemoryReader &);

} // namespace hexlab
