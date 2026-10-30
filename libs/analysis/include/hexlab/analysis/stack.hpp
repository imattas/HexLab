#pragma once

#include "hexlab/analysis/abi.hpp"
#include "hexlab/analysis/analysis_export.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/image/metadata.hpp"

#include <cstdint>
#include <optional>

namespace hexlab {

enum class StackArgumentAbi : std::uint8_t {
    x86_32_near_call,
    sysv_x86_64,
    windows_x64,
    aapcs64,
    riscv32,
    riscv64,
    // AAPCS32 overflow arguments at or above the callee's entry SP.
    aapcs32,
    // MIPS O32 overflow arguments after the four-word argument home area.
    mips_o32,
    // PPC64 ELFv2 overflow arguments after the eight-doubleword parameter area.
    ppc64le_elfv2,
    // x86-32 stack arguments covered by a consistent `ret imm16` epilogue.
    x86_32_callee_cleanup,
    // MIPS N64 overflow arguments beyond the eight 64-bit argument slots.
    mips_n64
};

struct StackSlotAccess {
    Address instruction;
    bool read = false;
    bool written = false;
    bool address_taken = false;
    bool operator==(const StackSlotAccess &) const = default;
};

enum class StackCallArgumentSourceKind : std::uint8_t {
    x86_push, aarch64_store, windows_x64_shadow_store, riscv_store, powerpc_store, mips_store, aapcs32_store
};
struct StackSlotCallArgument {
    Address source_instruction;
    Address call_instruction;
    StackCallArgumentSourceKind source_kind = StackCallArgumentSourceKind::x86_push;
    bool operator==(const StackSlotCallArgument &) const = default;
};

// A conservative local/argument slot inferred from a direct stack-relative
// memory operand. Offsets are measured from the stack pointer at function
// entry; this makes frame-pointer and stack-pointer references comparable.
struct StackSlot {
    std::int64_t offset_from_entry_sp = 0;
    std::uint16_t width = 0;
    bool read = false;
    bool written = false;
    std::vector<Address> accesses;
    bool address_taken = false;
    // Per-instruction access semantics. `accesses` remains the compact unique
    // location list used by existing consumers; this records which locations
    // read, write, or take the slot's address.
    std::vector<StackSlotAccess> access_details;
    // Caller-side argument/home-area evidence. Each row links the source
    // stack operation to its immediately following call boundary.
    std::vector<StackSlotCallArgument> outgoing_call_arguments;
    // x86-32 cdecl/stdcall-compatible incoming stack argument location. The
    // return-address cell at entry-SP+0 is intentionally excluded.
    bool incoming_argument = false;
    std::optional<StackArgumentAbi> incoming_argument_abi;
    bool operator==(const StackSlot &) const = default;
};

struct StackFrameAnalysis {
    std::vector<StackSlot> slots;
    // Exact high-water stack allocation from entry SP, when every reachable
    // stack-depth path is known. A value of zero is a proven frameless body;
    // nullopt means the recovered flow cannot establish a complete extent.
    std::optional<std::uint64_t> maximum_stack_allocation_bytes;
    // False when the function is incomplete or a stack-relative access could
    // not be assigned a unique offset across its incoming control-flow paths.
    bool complete = true;
};

HEXLAB_ANALYSIS_EXPORT Result<StackFrameAnalysis>
analyze_stack_frame(const FunctionRecord &, const FunctionSnapshot &, std::stop_token,
                    std::optional<CallingConvention> image_default_convention = {});

// Select platform-default x86-64 ABIs from image format, and PPC64 ELFv2 only
// from its explicit ELF machine, class, endian, and ABI flag evidence. Raw and
// unknown formats deliberately provide no convention.
HEXLAB_ANALYSIS_EXPORT std::optional<CallingConvention>
default_stack_calling_convention(const ImageMetadata &);

} // namespace hexlab
