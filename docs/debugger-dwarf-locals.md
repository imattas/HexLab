# Live DWARF locals in the debugger

When the target is stopped on a thread, the debugger panel resolves that
thread's current PC into the active project's image and function map. The
`DWARF locals / parameters` table then lists persisted variables whose owning
function and location-list range cover that PC. It evaluates the saved
location expression against the selected thread's live registers and bounded
debugger memory reads.

The table distinguishes parameters from locals and shows whether a variable is
in memory, a DWARF register, or a scalar value. Memory locations display an
address and a type-sized scalar preview when the imported type provides a
supported size. Unsupported expressions,
unavailable registers, and unreadable memory remain visible as unavailable
values rather than being guessed.

Expression evaluation includes bounded integer arithmetic and stack operations,
signed comparisons, and `DW_OP_bra` / `DW_OP_skip` control flow. Branch targets
must land on an operation boundary or the expression end. Evaluation is capped
at 4,096 decoded operations, 65,536 executed operations, 64 stack entries, and
4,096 memory reads per expression. Register values and memory remain explicit
inputs from the selected stopped thread. Expression calls, typed operations,
and implicit-pointer operations are not imported or evaluated. The symbol
evaluator supports `DW_OP_entry_value` when callers supply separate entry-state
register and memory readers, but this desktop table does not currently supply
those readers, so locations requiring entry-state data remain unavailable here.
The evaluator also decodes and handles `DW_OP_form_tls_address`. On Linux
AArch64, the desktop passes the selected stopped thread's `NT_ARM_TLS`
`TPIDR_EL0` snapshot as the TLS base and applies the DWARF offset at the target
address width. If the backend or kernel does not provide that register, or on
other architectures, the resolver stays absent and affected TLS locations
remain explicitly unavailable. The desktop does not infer a TLS base from
module layout or another thread's state.
`DW_OP_implicit_value` blocks up to eight bytes are displayed as scalar values
using the image's target byte order. Larger blocks are decoded within a 64 KiB
input cap but remain unavailable because the current scalar location result
cannot preserve arbitrary byte sequences.
DWARF 5 defines comparison and branch behavior in section 2.5.1.5:
[DWARF v5 standard](https://dwarfstd.org/doc/DWARF5.pdf).

Composite locations from `DW_OP_piece` and `DW_OP_bit_piece` are shown as an
ordered piece list. Each entry reports its destination bit offset, size,
source bit offset, and register, memory address, or scalar source. Unavailable
pieces remain explicit. Memory pieces show only the bytes covering the source
bit range, capped at 32 bytes per piece; register previews are capped at 32
bytes. The table does not concatenate pieces or claim to decode an aggregate
value, and it limits each row to 24 displayed pieces.

Known-size values through 256 bytes receive a bounded preview. Values up to
one machine word are shown as scalars; wider memory-backed values show their
exact bytes. A wider register-backed value is shown only when the debugger
supplied enough bytes for the whole type, so a short register is never silently
truncated or read past its available storage. Values with unknown, zero, or
larger sizes remain unpreviewed.

Runtime addresses are translated through the module containing the stopped
PC, using the image's preferred base or the lowest mapped segment as the
link-time base. The active workspace document supplies symbols and imported
DWARF records, so the matching binary must be open in the workspace. Register
number mapping currently covers x86, x86-64, ARM, AArch64, and RISC-V naming
conventions. Frame-base expressions use a recognized frame-pointer register;
the live frame uses a recognized frame-pointer register when no unwind-derived
frame base is available. The frame selector walks caller frames using
bounded x86-64/AArch64 ELF64, ARM32/Thumb ELF32 and RV32/RV64 `.eh_frame` CFI and the existing x86-64/AArch64 Mach-O
`.eh_frame` and compact-unwind evaluators. It keeps the live frame first, then
adds callers only while each recipe recovers a nonzero return PC and strictly
increasing CFA/stack pointer. Each recovered caller carries its CFA into
`DW_OP_call_frame_cfa` and frame-base evaluation, and its restored registers
are used to evaluate that caller's local-variable locations. The walk is
capped at 128 frames and stops on missing recipes, unreadable saved state,
repeated PCs, invalid stack progress, or a return PC outside the matched
module. It uses the matched image's preferred base for runtime-to-link-time PC
translation.

ELF caller-frame unwinding uses validated `.eh_frame` records with a 1 MiB
combined CIE/FDE program bound. The existing x86-64/AArch64 bridge requires
little-endian ELF; AArch64 caller state includes X19-X30, D8-D15, SP and PC.
ARM32/Thumb and RV32/RV64 accept either ELF byte order and support bounded
integer CFA and saved-register rules, including register-to-register and
value-offset recovery. CFI expressions, floating/vector rules, vendor rules,
ARM EHABI and RISC-V alternate signal return columns remain unsupported on
these new paths. Saved words and recovered registers use four bytes on
ARM32/RV32 and eight bytes on RV64. Unspecified volatile registers remain
unavailable; recovered CFA feeds selected-frame locals. ARM code lookups clear
the Thumb state bit while register snapshots retain it. RISC-V PC is carried
separately from DWARF registers because column 32 denotes F0. See
[ELF unwind rules and bounds](elf-dwarf-unwind.md) for exact register/ABI limits.
These paths require matching stopped-thread or remote register snapshots and
memory; they add no native backend. Mach-O caller-frame
unwinding supports x86-64 and AArch64; AArch64 context conversion includes
X19-X30, SP, PC, and D8-D15, and live FP/LR aliases map to X29/X30. Other
formats and architectures still show the live frame only. Frame-base
attributes are not persisted from DWARF, so a caller with a recovered CFA
uses that CFA as the frame-base fallback.
