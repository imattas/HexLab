# ELF ARM32 and RISC-V debugger stack frames

The desktop frame selector can recover caller frames from retained, validated
ARM32/Thumb ELF32 and RV32/RV64 `.eh_frame` CIE/FDE programs when the stopped
target session supplies matching full-width integer registers and memory.
Existing exact module/path and image-layout checks still apply. This feature
does not add native ARM32/RISC-V process debugging backends.

ARM names R0-R15 plus SP/LR/PC, FP=R11, IP=R12, SL=R10 and SB=R9 map to
integer DWARF registers. RISC-V X0-X31 and integer ABI aliases map to their
integer DWARF registers, including FP=S0/X8. RISC-V PC has its own recovered
field because DWARF register 32 means F0. Caller snapshots preserve four-byte
ARM32/RV32 and eight-byte RV64 values in the ELF byte order. Both byte orders
are supported by these integer CFI paths. Conflicting aliases stop recovery.

ARM recovery retains available R4-R8, R10-R11 and LR unless CFI changes them;
platform-dependent R9 requires an explicit rule. RISC-V recovery retains
available RA, GP, TP, S0-S11 and constant X0. Explicit integer rules can
recover additional registers. Unspecified volatile registers are unavailable.
The recovered CFA becomes SP, and the ordinary ABI return register (ARM LR or
RISC-V RA) supplies PC. Thumb's raw return-state bit remains in the recovered
registers; code addresses clear it for frame lookup and local-variable ranges.

Supported rules are register-plus-offset CFA, word-at-CFA-offset, value at
CFA-offset, same/undefined and register-to-register recovery, with standard
location advances, restore and remember/restore-state instructions. The
combined program is limited to 1 MiB, 65,536 interpreted operations and 64
saved states. Integer overflow, unsupported rules/register banks, unreadable
state, invalid return alignment, absent/overlapping FDEs or non-increasing SP
stop recovery. The UI also stops at repeated PCs, an invalid executable-code
mapping, a caller outside the module or 128 frames.

Expressions, `set_loc`, vendor CFI, floating/vector/control registers, ARM
`.ARM.exidx`/EHABI, RISC-V alternate signal return columns, embedded-register
ABIs, RV64ILP32 and unknown RISC-V ELF flag extensions remain unsupported.
There is no cross-module frame walk. Existing x86-64/AArch64 ELF recovery
continues through its little-endian 64-bit bridge.

See [ELF DWARF unwind](../../../docs/elf-dwarf-unwind.md) for the exact
instruction list and ABI references. No builds, tests or live-target checks
were run for this extension; serial loader and desktop builds remain follow-up.
