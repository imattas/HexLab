# ELF core dumps

`load_elf` accepts ELF `ET_CORE` files and maps nonempty `PT_LOAD` ranges into
the normal image model. Segment permissions, virtual addresses, captured file
extents, and zero-filled tails use the existing ELF load-segment rules. The
original core file remains the byte source, so image reads keep file-offset
provenance. Core images have no executable entry point and do not run the
executable/shared-object symbol, DWARF, unwind, or relocation import passes.

Generic `PT_NOTE` records remain available in `ElfMetadata::notes`. Linux
`CORE`/`LINUX` `NT_PRPSINFO` notes additionally expose the process IDs,
executable name, and bounded argument string through `ElfMetadata::core` for
both ELF32 and ELF64. ELF32 uses its 128-byte layout (32-bit flags, uid/gid and
IDs, command name at byte 32, and arguments at byte 48); ELF64 uses its
136-byte layout with 64-bit flags alignment and strings at bytes 40/56. Short
records remain generic notes with a core diagnostic; trailing extension bytes
remain preserved in the original generic note.
`NT_PRSTATUS` notes expose per-thread IDs and the current signal. Register values
are decoded for little-endian ELF64 x86-64, AArch64, and RISC-V cores. x86-64
retains the 27 Linux gregset entries, and AArch64 retains `x0`–`x30`, `sp`, `pc`, and
`pstate`, and RISC-V retains `pc`, `ra`, `sp`, `gp`, `tp`, `t0`-`t6`,
`s0`-`s11`, and `a0`-`a7`. Register-note file offsets point to the source note
header; exact register names and values live in the structured thread record.

## ELF32 Linux register contexts

Linux `CORE`/`LINUX` `NT_PRSTATUS` now also decodes bounded ELF32 gregsets.
The common prefix is 72 bytes: the two 32-bit signal masks at offsets 16 and 20
are followed by PID/PPID/PGRP/SID at offsets 24/28/32/36 and four old 32-bit
timevals. This corrects the previous ELF32 ID extraction, which read the masks
as IDs. General registers start at payload offset 72.

| ELF machine / layout | Byte order | Gregset slots / named values | Exact record bytes |
| --- | --- | --- | --- |
| i386, `linux-i386` | Little | 17 / 17, all stored in 32-bit words | 144 |
| ARM32, `linux-arm32` | Little or big | 18 / 18, all stored in 32-bit words | 148 |
| MIPS O32, `linux-mips-o32` | Little or big | 45 / 38, all stored in 32-bit words | 256 |
| RISC-V32, `linux-riscv32` | Little | 32 / 32, all stored in 32-bit words | 204 |

i386 order is `ebx`, `ecx`, `edx`, `esi`, `edi`, `ebp`, `eax`, `ds`, `es`,
`fs`, `gs`, `orig_eax`, `eip`, `cs`, `eflags`, `esp`, `ss`. ARM order is
`r0` through `r12`, `sp`, `lr`, `pc`, `cpsr`, `orig_r0`; `r11` and `r12`
retain their canonical numbered names rather than the `fp`/`ip` aliases.

MIPS O32 slots 0–5 and 44 are padding/unused and are omitted from named values.
Slots 6–37 map to `r0`–`r31`, followed by `lo`, `hi`, `pc` (CP0 EPC),
`badvaddr`, `status`, and `cause` at slots 38–43. Linux deliberately writes
zero for unsaved `r26/r27` (`k0/k1`); these raw stored words remain visible with
`kernel_placeholder = true`, and are not represented as captured hardware
values. Slot indices and field offsets preserve the original gaps.

RISC-V order is `pc`, `ra`, `sp`, `gp`, `tp`, `t0`–`t2`, `s0/s1`, `a0`–`a7`,
`s2`–`s11`, `t3`–`t6`. The note contains PC plus x1–x31; no x0 word is
invented. ELF32 values are zero-extended from their stored 32-bit words.
Register `bits` describes stored gregset width, including full words holding
x86 segment selectors; it does not assert a wider architectural selector.

Linux register interpretation requires System V or Linux OSABI with ABI version
zero. ARM accepts the legacy ABI without APCS-26, or EABI versions 4/5. Other ARM
ABI versions remain generic. MIPS accepts O32 or the legacy zero ABI field with
`EF_MIPS_ABI2` clear; N32, O64 and EABI variants remain generic. RV32E and
big-endian i386/RISC-V remain unsupported. RV64E is likewise not interpreted.
Floating ABI choices do not fabricate
floating-point register contexts.

Each new ELF32 record must have its exact supported length, including the final
four-byte `pr_fpvalid` field. Short prefixes, truncated gregsets and missing
tails are malformed; unexpected larger records remain unsupported instead of
being guessed as an ABI variant. No partial register vector is emitted.
`floating_point_valid` retains the raw flag and does not imply that FP values
were decoded. Existing ELF64 x86-64/AArch64 register order and acceptance of
the established general-register extent are preserved.

## Provenance and CLI output

Structured thread records now retain `payload_file_offset`, optional
`gregset_file_offset`, `gregset_slots`, `register_word_bits`, byte order and a
layout name. Every named register carries its stored width, original gregset
index and exact source file offset, as well as the numeric value. Original note
headers and descriptions remain in `ElfMetadata::notes` for every outcome.
Register vectors and names are charged against the shared metadata budget
before retained allocations, and source-offset arithmetic is checked.

CLI ELF inspection labels `ET_CORE` as `CORE` and prints thread IDs, signals,
decode status, layout, raw/named counts, widths, byte order, diagnostics and note/
payload/gregset/field source offsets. New thread output is capped at 256 rows and
4,096 register rows across those threads; omitted counts are explicit. These
display limits do not truncate the loader's structured metadata.

## Other notes and limitations

Linux `NT_SIGINFO` notes retain the signal, errno, and signal code with note and
payload file offsets. For `SIGILL`, `SIGTRAP`, `SIGBUS`, `SIGFPE`, and `SIGSEGV`,
the class-sized `si_addr` field is also exposed as a fault address. The CLI
`inspect` output prints these records. Signal address decoding follows the
Linux ELF class layout; it does not decode the signal-specific union fields
other than `si_addr`.

Linux `NT_AUXV` notes decode ELF-class-sized auxiliary-vector pairs up to the
required `AT_NULL` terminator. Each retained type/value pair carries its source
note and exact entry file offsets. `NT_FILE` notes decode mapping count, page
size, address ranges, page-based file offsets (normalized to bytes), and
NUL-terminated module paths for ELF32 and ELF64, in either byte order. Mapping
rows retain note and table-entry file offsets. Truncated tables or path lists,
invalid ranges, missing terminators, zero page sizes, and arithmetic overflow
are reported as core diagnostics without discarding other notes. Both decoders
enforce the shared record and metadata budgets.

Unsupported register architectures, byte orders and ABI variants remain generic
notes with an explicit per-thread diagnostic. A truncated process or thread
record is retained as malformed metadata and marks the loaded image incomplete;
it does not discard other core mappings. For a Linux `NT_FPREGSET` note
immediately following a successfully decoded `NT_PRSTATUS`, the loader attaches
typed floating-point state to that thread. It accepts only little-endian
x86-64 payloads of exactly 512 bytes (control/address fields, eight 128-bit
x87 storage slots, and sixteen XMM registers) and AArch64 payloads of exactly
528 bytes (`v0`-`v31`, `fpsr`, and `fpcr`). Linux ARM32 `LINUX`/`NT_ARM_VFP`
notes immediately after a decoded thread retain `d0`-`d31` and `fpscr` from
the exact 260-byte user VFP record. Each field retains its note,
payload, and exact file offset. This ordering rule avoids guessing a thread
owner when a note is detached or interleaved. Unmatched notes, unsupported
machines or byte orders, and other payload sizes remain available in the
generic note list and add an explicit core diagnostic; no layout is inferred
from a partial prefix. CLI `inspect` prints decoded FP registers under their
owning thread, capped at 64 FP states and the existing 256-thread output limit.
The retained values count against the loader's shared metadata budget. Other OS-specific
notes and architecture-specific signal frames are not decoded. Missing pages
are not reconstructed and absent core data is not treated as a live process
state.

The Linux note layouts follow the kernel's [`elfcore.h`](https://github.com/torvalds/linux/blob/master/include/linux/elfcore.h)
and AArch64 [`user_pt_regs`](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/ptrace.h)
definitions. The x86-64 general-register order follows Linux's ELF core ABI.
The ARM32 VFP payload size follows [`ARM_VFPREGS_SIZE`](https://github.com/torvalds/linux/blob/master/arch/arm/include/uapi/asm/ptrace.h).

The ELF32 layouts follow Linux's [i386 user register structure](https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/user_32.h),
[ARM register structure](https://github.com/torvalds/linux/blob/master/arch/arm/include/uapi/asm/ptrace.h),
[MIPS32 slot definitions](https://github.com/torvalds/linux/blob/master/arch/mips/include/uapi/asm/reg.h),
[MIPS register dump rules](https://github.com/torvalds/linux/blob/master/arch/mips/kernel/process.c),
and [RISC-V user register structure](https://github.com/torvalds/linux/blob/master/arch/riscv/include/uapi/asm/ptrace.h).

ELF64 RISC-V decoding uses the Linux `user_regs_struct` order from the same
RISC-V UAPI definition. It requires little-endian ELF64, the Linux/System V
OSABI convention already used for the other Linux thread layouts, ABI version
zero, and `EF_RISCV_RVE` clear. The 32 stored words begin at the ELF64
`NT_PRSTATUS` gregset offset of 112 bytes; their field provenance is retained
like the existing x86-64, AArch64, and ELF32 register records. The parser
requires a complete 32-word set but does not infer floating-point state or
interpret extra note bytes as a RISC-V extension.

The ELF32 register-context increment received source review only; no tests,
generated fixtures or builds were run. The ELF64 RISC-V register-context
increment also received source review only; no tests or builds were run.
