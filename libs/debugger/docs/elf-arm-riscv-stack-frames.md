# ELF integer-only debugger stack frames

The desktop frame selector can recover caller frames from retained, validated
ARM32/Thumb ELF32, MIPS32 ELF32 and RV32/RV64 `.eh_frame` CIE/FDE programs when the stopped
target session supplies matching full-width integer registers and memory.
Existing exact module/path and image-layout checks still apply. This feature
does not add native ARM32/RISC-V process debugging backends.

ARM names R0-R15 plus SP/LR/PC, FP=R11, IP=R12, SL=R10 and SB=R9 map to
integer DWARF registers. MIPS32 GPR0-GPR31 and O32 names (`zero`, `at`, `v0`
through `ra`) map to integer DWARF registers. RISC-V X0-X31 and integer ABI aliases map to their
integer DWARF registers, including FP=S0/X8. RISC-V PC has its own recovered
field because DWARF register 32 means F0. Caller snapshots preserve four-byte
ARM32/MIPS32/RV32 and eight-byte RV64 values in the ELF byte order. Both byte orders
are supported by these integer CFI paths. Conflicting aliases stop recovery.

ARM recovery retains available R4-R8, R10-R11 and LR unless CFI changes them;
platform-dependent R9 requires an explicit rule. RISC-V recovery retains
available RA, GP, TP, S0-S11 and constant X0. MIPS32 retains available S0-S7
and S8/FP; explicit integer rules can
recover additional registers. Unspecified volatile registers are unavailable.
The recovered CFA becomes SP, and the ordinary ABI return register (ARM LR or
RISC-V RA or MIPS32 RA) supplies PC. MIPS32 return addresses must be word aligned.
Thumb's raw return-state bit remains in the recovered
registers; code addresses clear it for frame lookup and local-variable ranges.

For MIPS16/microMIPS, the desktop selects the compressed dialect from an
explicit `MIPS16` or `MICROMIPS` marker register whose value is exactly one,
or an exact GDB XML architecture declaration `mips:16` or `mips:micromips`.
These are GNU BFD architecture names; the remote backend derives the 32/64-bit
register family from the `pc` register's width, falling back to one uniquely
typed `code_ptr` register when `pc` is absent. Conflicting dialect declarations,
malformed marker values, and a marker explicitly disabling the declared
dialect stop frame recovery. Missing metadata keeps classic MIPS behavior.
In compact mode bit zero is retained in the recovered RA and cleared from the
frame PC used for module/code lookup. Classic MIPS keeps the word-alignment
rule. No mode is guessed from an odd PC or RA alone.

Remote register snapshots now preserve the target-description architecture
string and each register's optional `type` identifier, capped at 128 bytes
each. Architecture declarations across included annexes must agree exactly.
The backend also derives byte order from recognized GDB architecture names:
`aarch64` and `aarch64: little endian` mean little-endian;
`aarch64_be` and `aarch64: big endian` mean big-endian; `armeb` and ARM names
ending in `eb` mean big-endian. Unsuffixed ARM names do not imply byte order.
These inferences are checked against any explicit target XML `endian` value,
so conflicting descriptions remain errors. Other architecture spellings leave
byte order undeclared and retain the existing fallback behavior.
The generic `code_ptr` type supplies PC-width evidence only; arbitrary custom
type names do not establish a MIPS compression dialect. This follows the
[GDB target-description format](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Target-Description-Format.html)
and the [GNU BFD MIPS architecture names](https://raw.githubusercontent.com/RTEMS/sourceware-mirror-binutils-gdb/master/bfd/cpu-mips.c).

Supported rules are register-plus-offset CFA, word-at-CFA-offset, value at
CFA-offset, same/undefined and register-to-register recovery, with standard
location advances, restore and remember/restore-state instructions. The
combined program is limited to 1 MiB, 65,536 interpreted operations and 64
saved states. Integer overflow, unsupported rules/register banks, unreadable
state, invalid return alignment, absent/overlapping FDEs or non-increasing SP
stop recovery. The UI also stops at repeated PCs, an invalid executable-code
mapping, a caller outside the module or 128 frames.

Expressions, `set_loc`, vendor CFI, floating/vector/control registers, ARM
`.ARM.exidx`/EHABI, MIPS compact modes without explicit marker/architecture metadata, MIPS64 frame recovery, custom type interpretation, RISC-V alternate signal return columns, embedded-register
ABIs, RV64ILP32 and unknown RISC-V ELF flag extensions remain unsupported.
There is no cross-module frame walk. Existing x86-64/AArch64 ELF recovery
continues through its little-endian 64-bit bridge.

See [ELF DWARF unwind](../../../docs/elf-dwarf-unwind.md) for the exact
instruction list and ABI references. The target-description metadata extension
passed a Windows x64 Debug `hexlab_debugger` build. No tests or live-target
checks were run; desktop integration and MIPS stub runtime validation remain
follow-up work.
