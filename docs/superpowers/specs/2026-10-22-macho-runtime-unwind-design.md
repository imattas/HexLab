# Mach-O runtime compact-unwind evaluation

## Intent and scope

HexLab already validates linked-image `__unwind_info` indexes and preserves each function's compact-unwind encoding. The next step is an explicit runtime evaluator: given a program counter, register context, and bounded stack-memory reader, locate the function's validated compact-unwind entry and compute the caller context for supported x86_64 and arm64 frame recipes. This is a debugger and exception-analysis primitive; function roots alone do not satisfy it.

This slice supports recipes whose semantics can be established from the compact encoding without executing instructions: x86_64 RBP-frame (including encoded RBX/R12-R15 saves) and immediate-stack (including its saved-register permutation) modes; arm64 frame and frameless modes with X19-X28 and D8-D15 saves; ordinary non-authenticated ARM64 frame records on arm64e slices; and the arm64e authenticated-frame recipe, which reports LR signing state from the bounded encoded `pacibsppc` offset without authenticating the pointer. x86_64 indirect-stack modes require instruction-byte reads and remain unsupported. DWARF modes identify FDEs in `__eh_frame`, but FDE/CIE evaluation is not implemented and returns a precise unsupported error. Missing entries, malformed encodings, arithmetic overflow, and failed memory reads remain explicit errors. It does not claim full stack walking or exception dispatch.

## Public interface

Add `hexlab/loaders/macho_unwind.hpp` with:

- `MachOUnwindRegister`: architecture-neutral register identifiers for `x86_64.rbp`, `x86_64.rsp`, `x86_64.rip`, `x86_64.rbx`, `x86_64.r12-r15`, and `arm64.x29`, `arm64.x30`, `arm64.sp`, `arm64.pc`, `arm64.x19-x28`, and `arm64.d8-d15` (D registers are preserved as raw 64-bit values).
- `MachOUnwindContext`: map of register identifier to 64-bit value.
- `MachOUnwindMemoryReader`: callback `std::optional<std::uint64_t>(std::uint64_t address, std::uint8_t width)`; only aligned-or-unaligned 8-byte reads are requested, as specified by each recipe, and callers decide memory accessibility.
- `MachOUnwindResult`: caller context, CFA, source function address, encoding, and compact-unwind provenance.
- `evaluate_macho_unwind(const MachOMetadata &, Address pc, const MachOUnwindContext &, const MachOUnwindMemoryReader &) -> Result<MachOUnwindResult>`.

Function lookup uses validated `compact_unwind_functions`, selecting the nearest entry at or below PC and proving the interval with the next higher entry from the same compact-unwind section and selected slice. A PC at or beyond the last known entry is rejected because the current parser drops the section sentinel and no end bound is available. The result records the selected function start, while evaluation works for any PC inside the proven interval.

The result identifies each recovered caller register and preserves caller-provided registers that the selected recipe does not modify. Missing required registers return `ErrorCode::malformed`; failed stack reads and unproven PC intervals return `ErrorCode::out_of_bounds`; unsupported recipe encodings return `ErrorCode::unsupported`.

## Recipe semantics

- x86_64 RBP frame mode: CFA = RBP + 16; encoded nonvolatile registers are restored from their RBP-relative save slots; saved RBP is read at CFA-16; return PC at CFA-8; caller RSP = CFA. Duplicate, invalid, or overlapping save layouts are rejected.
- x86_64 immediate stack mode: stack size is the encoded immediate field times 8; the encoded register permutation is decoded over RBX/R12-R15/RBP and restored from the contiguous area immediately before the return address; CFA = RSP + stack size; return PC is read after those saves; caller RSP = CFA. Invalid permutation ranks and overflow layouts are rejected.
- arm64 frame mode: CFA = X29 + 16; encoded X19-X28 and D8-D15 pairs are restored in ABI register order immediately below the frame record; saved X29 at CFA-16 and X30 at CFA-8; caller SP = CFA and caller PC = saved X30.
- arm64 frameless mode: stack size is the encoded field times 16; encoded X19-X28 and D8-D15 pairs are restored from the top of the allocated frame in register order; caller SP is the post-save stack address and caller PC comes from X30.

x86 indirect-stack and DWARF FDE modes remain unsupported and must never be treated as a no-op recipe. The arm64e authenticated-frame mode is limited to ARM64E slices and an encoded PAC offset within the proven compact-unwind function interval; the evaluator reports signed state only and does not perform pointer authentication. DWARF mode errors state that FDE evaluation is not implemented.

## Validation and integration

All arithmetic is checked. Memory is read only through the supplied callback, and a missing value fails rather than becoming zero. Architecture is derived from selected Mach-O slice metadata and must agree with the compact-unwind recipe. The API is side-effect free and does not mutate image metadata.

Add tests for successful x86_64 frame/immediate and arm64 frame evaluation; unbounded PC/register/memory failures; unsupported/DWARF encodings; arithmetic overflow and malformed register-save permutations. Keep implementation scoped to Mach-O files; root integration needs one loader source line and one test target/test registration line.

## Future stage: DWARF

The current repository parses ELF `.eh_frame` with a format-sensitive implementation, but that source is not a dependency-free general CFI library. This slice will not copy it or reinterpret license obligations. Mach-O `__eh_frame` FDE/CIE and LSDA call-site parsing require a separately reviewed design and focused parser. DWARF compact-unwind encodings return unsupported until that work lands.
