#pragma once

#include "hexlab/analysis/analysis_export.hpp"
#include "hexlab/types/types.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace hexlab {

// Avoid the platform's `cdecl` macro in public identifiers.
enum class CallingConvention {
    sysv_x86_64, windows_x64, x86_32_cdecl, aapcs64,
    x86_32_stdcall, x86_32_fastcall, x86_32_thiscall, riscv32, riscv64,
    // Appended to preserve the ordinal values of previously shipped entries.
    x86_32_vectorcall, windows_x64_vectorcall, aapcs32,
    // Explicit MIPS ABI selectors; only Linux N64 is currently classified.
    mips_o32, mips_n32, mips_n64,
    // Explicit little-endian PowerPC64 ELFv2; ELF class alone cannot select it.
    ppc64le_elfv2
};
enum class AbiLocationKind { register_, stack };
enum class AbiStackCleanup { caller, callee };
enum class AbiLocationRole { value, hidden_result_argument, returned_buffer_address };

struct AbiLocation {
    AbiLocationKind kind = AbiLocationKind::register_;
    std::string register_name;
    // Byte offset from the callee's stack pointer on function entry.
    std::uint64_t stack_offset = 0;
    std::uint64_t size = 0;
    std::uint64_t alignment = 1;
    // Byte offset within the value, used when a scalar or aggregate is split.
    std::uint64_t value_offset = 0;
    // Physical width of the register or stack container. Zero means `size`.
    // RISC-V uses XLEN containers; vectorcall reports SIMD register widths.
    std::uint64_t placement_size = 0;
    // Indirect aggregate results use both an incoming hidden buffer pointer
    // and, on SysV AMD64/Microsoft x64, the returned copy of that pointer.
    AbiLocationRole role = AbiLocationRole::value;
    // True for a second ABI-required copy of the same call-site argument.
    // Microsoft x64 varargs duplicate floating values into the corresponding GPR.
    bool duplicate = false;
};

struct AbiValueLocation {
    bool supported = true;
    std::string reason;
    // One location for ordinary scalars; multiple locations describe split
    // scalar or aggregate values.
    std::vector<AbiLocation> locations;
    // True when the location carries an address for an aggregate or wide scalar.
    bool indirect = false;
};

struct AbiSignatureClassification {
    CallingConvention convention = CallingConvention::sysv_x86_64;
    std::vector<AbiValueLocation> arguments;
    AbiValueLocation result;
    // The ABI-mandated hidden pointer used to receive an indirect result.
    // This is separate from `arguments`, so declared parameter indices remain stable.
    AbiValueLocation hidden_result_pointer;
    // The implicit `this` pointer is distinct from declared parameters and is
    // present only for x86-32 thiscall signatures.
    AbiValueLocation implicit_this;
    // Source metadata adjustment associated with a method's `this` pointer.
    // Classification records but does not apply this displacement.
    std::int32_t this_adjustment = 0;
    std::uint8_t pointer_size = 0;
    std::uint8_t stack_alignment = 0;
    std::uint8_t stack_slot_size = 0;
    std::uint16_t shadow_space = 0;
    // Explicit stack argument area size, rounded to slot granularity; excludes
    // hidden result pointers.
    std::uint64_t stack_argument_bytes = 0;
    AbiStackCleanup stack_cleanup = AbiStackCleanup::caller;
    // Bytes popped by the callee on return, including any hidden stack result
    // pointer. Zero for caller-cleanup conventions.
    std::uint64_t callee_pop_bytes = 0;
    bool complete = true;
    // System V AMD64 variadic-call value for %al: number of XMM argument
    // registers used, in the range 0..8. Zero for other conventions.
    std::uint8_t sysv_vector_register_count = 0;
};

// Classifies supported scalar, aggregate, and vector values for the named
// conventions. riscv32/riscv64 select the base integer psABI; values wider than
// 2*XLEN are represented indirectly. Microsoft vectorcall supports native x86
// and Windows x64, including bounded homogeneous vector aggregates. Baseline
// 8/16-byte SysV AMD64 and AAPCS64 vectors, plus 16-byte Microsoft x64 vectors,
// are classified where their lane shape is modeled. Unsupported conventions,
// target-dependent vector widths, and unresolved types remain explicit.
// MIPS N64 is explicitly selected and models eight argument slots, scalar
// GPR/FPR locations, bounded integer-class aggregate chunks, and hidden result
// pointers for larger aggregate returns. O32 and N32 are recognized but unsupported.
// AAPCS32 models the base PCS with R0-R3, split composites, and hidden result
// pointers. It does not model VFP/Advanced SIMD register allocation or
// AAPCS32 variadic call-site promotions.
// PowerPC64 ELFv2 is selected explicitly as ppc64le_elfv2. It models binary
// float/double, 1/2/4/8-byte integer and pointer scalars, and bounded C-like
// integer-only structures with complete 8-byte chunks. See
// docs/abi-classification.md for the exact limits and stack-area semantics.
// For Microsoft x64, layout-only C-compatible aggregates of exactly 1, 2, 4,
// or 8 bytes are passed/returned as integer values. Other aggregate parameters
// are passed indirectly in their positional argument slot; other aggregate
// results use the hidden result pointer. The type model has no C++ triviality
// metadata, so this rule does not claim support for non-trivial class ABI cases.
HEXLAB_ANALYSIS_EXPORT AbiSignatureClassification
classify_abi_signature(CallingConvention convention, const types::Type &function_type);

// Uses an explicitly retained function-type convention where the classifier
// has a matching model. platform_default keeps the caller-selected ABI.
HEXLAB_ANALYSIS_EXPORT AbiSignatureClassification
classify_abi_signature(const types::Type &function_type, CallingConvention platform_default);

// Classifies a persisted C++ method declaration, whose receiver is stored
// separately from its ordinary function signature. Windows x64 is supported;
// static methods have no receiver slot. Non-static methods consume ordinal
// position zero and shift explicit parameters. `this_adjustment` is retained
// as metadata for the caller; the classifier cannot apply object adjustments.
HEXLAB_ANALYSIS_EXPORT AbiSignatureClassification
classify_abi_method(CallingConvention convention, const types::Method &method);

// Classifies one variadic call from its prototype and actual argument types.
// Fixed arguments use the declared parameter types; arguments after the fixed
// parameter list use C default argument promotions. Only SysV AMD64 and
// Microsoft x64 variadic calls are supported. For Microsoft x64, duplicate
// floating argument locations are marked `AbiLocation::duplicate`; for SysV,
// `sysv_vector_register_count` supplies the required %al value.
HEXLAB_ANALYSIS_EXPORT AbiSignatureClassification
classify_abi_call(CallingConvention convention, const types::Type &function_type,
                  std::span<const types::TypePtr> actual_argument_types);

} // namespace hexlab
