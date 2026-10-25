# ELF AArch64 debugger stack frames

The desktop debugger uses validated ELF `.eh_frame` recipes to recover caller
frames for x86-64 and AArch64 targets. [ARM32/Thumb and RISC-V integer
CFI](elf-arm-riscv-stack-frames.md) have a separate width-aware path. The selected module must match the
project source path exactly, its runtime and image sizes must agree, and the
stopped PC must map into executable image bytes. Basename-only module matches
are not accepted.

For AArch64, the initial stopped-thread register context is translated to
DWARF register numbers. The existing bounded CFI evaluator recovers the
caller context, including X19-X30, D8-D15, SP, and PC. Recovered caller
register values feed the next frame's CFI evaluation and the selected-frame
local-variable view. Stack reads and register values follow the ELF image's
byte order. The existing x86-64/AArch64 ELF CFI bridge requires little-endian
instruction operands; big-endian recipes return unsupported.

Frame walking stops on an unavailable or unsupported recipe, missing memory or
register state, a non-increasing stack pointer, a repeated PC, a caller outside
the mapped module, or the existing 128-frame UI bound. CFI evaluation reads
only eight-byte stack words. Registers outside the evaluator's supported
callee-saved subset and unsupported CFI operations remain unavailable; this
does not implement a general platform unwinder or cross-module stack walk.
