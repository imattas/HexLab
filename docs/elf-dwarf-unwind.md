# ELF DWARF unwind function roots

The ELF loader can use `.eh_frame` and supported `.debug_frame` FDEs as function-root evidence. It retains each accepted range in `ElfMetadata::unwind_ranges`, including the source kind, section index and the file offset and size of the FDE that supplied the range. Function recovery adds those starts as `FunctionSeedKind::unwind` and carries the same source section and FDE byte extent in the seed, so the evidence remains attached to the recovered function and to cached analysis. The separate [`.debug_frame` reader](elf-debug-frame.md) handles ordinary unaugmented DWARF32/64 frame records and provides runtime CFI fallback when `.eh_frame` has no accepted FDE covering the selected PC.

The loader also parses version-1 `PT_GNU_EH_FRAME` headers into bounded lookup
indexes. It decodes the `.eh_frame` pointer, FDE count, and sorted
`initial_location`/FDE pointer pairs using supported absolute, PC-relative, and
data-relative `DW_EH_PE` encodings. Pointers must map to initialized `PT_LOAD`
bytes and initial locations must point into initialized executable memory.
The CLI shows the header encodings, addresses, and source offsets, capped at
128 table rows. This index is descriptive metadata: it does not replace the
section FDE parser, validate each FDE's CFI instructions, or change runtime
unwind selection. Unsupported encodings, malformed counts, unordered rows,
and out-of-segment pointers make unwind metadata partial.

The bounded `.eh_frame` reader handles linked ELF executables/shared objects for the loader's represented x86, x86-64, ARM, AArch64, MIPS32/MIPS64, and RISC-V32/64 machine IDs. It accepts CIE versions 1, 3, and 4 with either no augmentation or a `z` augmentation containing any subset and ordering of `P`, `L`, and `R` (including `z` alone). Each tag may appear once. `P` supplies the personality encoding and pointer, `L` supplies the FDE LSDA pointer encoding, and `R` supplies the FDE range encoding; without `R`, range addresses use the native absolute pointer format. Absolute and PC-relative fixed/LEB formats are supported. PC-relative fields are based on their encoded field address. Every FDE range must be nonempty, nonoverflowing, and wholly contained in initialized executable image bytes before it becomes a root.

CIE augmentation fields are read in declared string order inside the advertised augmentation byte extent. FDE CIE pointers are backward distances from the pointer field to the CIE record start (its length field); references to the CIE identifier field are rejected. FDE augmentation lengths are independently bounded by their records; an LSDA pointer is read when `L` supplies an encoding other than `DW_EH_PE_omit`. Both instruction programs start after the entire corresponding augmentation payload, including any trailing payload bytes. All ranges and CFI recipes from a section are published together only after that section has been accepted.

The validated FDE range also bounds function recovery: control flow that leaves
`[begin, begin + size)` stops at a function chunk boundary unless an explicit
user chunk definition overrides the metadata.

For ELF64 x86-64/AArch64, ELF32 ARM32/Thumb, and ELF32/ELF64 RISC-V, the loader retains the CIE/FDE code and data alignment factors, return register, and bounded instruction programs in `ElfMetadata::eh_frame_functions`. `evaluate_elf_unwind` evaluates the FDE covering a link-time PC against DWARF-numbered registers and a caller-provided memory reader, returning caller register values, `caller_pc`, CFA, function range, and FDE provenance. The desktop frame selector uses these results for caller frames and selected-frame locals. Missing/overlapping FDEs, unavailable registers/words, unsupported rules, overflow, and resource limits fail explicitly. The combined CIE/FDE program is capped at 1 MiB.

The legacy `eh_frame_functions` collection now also retains accepted
`.debug_frame` programs. `source_kind` distinguishes the formats on ranges,
recipes and runtime results. Runtime selection prefers `.eh_frame` at the
requested PC, then falls back to `.debug_frame`. Overlaps within the selected
source fail; an unsupported selected recipe does not trigger another-source
guess. Each section is accepted independently, so a malformed optional debug
section leaves accepted runtime CFI available and emits the existing partial
metadata diagnostic.

The existing x86-64/AArch64 evaluator uses the shared Mach-O CFI subset. It exposes the modeled x86-64 callee-saved registers, or AArch64 X19-X30, D8-D15, SP and PC. This bridge accepts only little-endian ELF because its fixed instruction operands are little-endian; big-endian AArch64 recipes return unsupported. Stack words on this path are eight bytes.

ARM32/Thumb, MIPS32 and RV32/RV64 use a separate integer-only evaluator. It accepts either ELF byte order, decodes fixed CFI operands in that order, and requests four-byte saved words for ELF32 or eight-byte saved words for ELF64. The reader returns a target-endian decoded scalar. Addresses, register values, CFI location advances, and complete saved-word extents must fit the target width; arithmetic overflow fails instead of truncating. The integer evaluator adds a shared 65,536-operation limit and a 64-level remembered-state limit.

Supported integer CFI instructions are `DW_CFA_nop`, primary `advance_loc`/`offset`/`restore`, `advance_loc1/2/4`, `offset_extended`, `restore_extended`, `undefined`, `same_value`, `register`, `remember_state`, `restore_state`, `def_cfa`, `def_cfa_register`, `def_cfa_offset`, `def_cfa_expression`, `offset_extended_sf`, `def_cfa_sf`, `def_cfa_offset_sf`, `val_offset`, `val_offset_sf`, `expression`, and `val_expression`. CFA rules can use a register plus checked signed offset or a CFA expression. Saved-register rules include CFA-relative word loads, CFA-relative values, expression-based word loads, value expressions, explicit same/undefined, or another live integer register. `DW_CFA_expression` evaluates to a saved-word address and reads one target-width word; `DW_CFA_val_expression` uses the expression result as the caller register value. Their expression stack starts with the computed CFA as required by DWARF, and the top item is the result; `DW_CFA_def_cfa_expression` starts with an empty stack. CFI expression blocks are limited to 64 KiB each; the evaluator shares the 65,536-operation budget and 64-item stack bound. Its scalar subset supports address/literal/constants, integer base-register-plus-offset, full target-word dereference, stack manipulation, plus/minus/`plus_uconst`, and nop. Constants and registers must fit the target width; DWARF arithmetic wraps at that width. Expressions that need typed data, call/entry values, frame-base or object context, partial-width dereferences, register-location values, or other unsupported operations fail explicitly. `DW_OP_call_frame_cfa` is rejected in CFI expression operands because the standard forbids it there. Rule sources always read the input context, so recovery order cannot change register-to-register results. Unsupported registers/opcodes encountered while establishing the selected row still fail explicitly, including `set_loc`, GNU/vendor forms, and floating/vector/control register banks.

The integer path assumes the ordinary caller SP equals CFA. An explicit SP rule must recover that same value; undefined or conflicting SP rules fail as unsupported. Stack-switching and signal-context layouts are not inferred.

The desktop ELF frame selector also recognizes the Linux x86-64 `rt_sigframe`
when the live stack contains exactly one bounded candidate. It scans at most
64 KiB above the stopped RSP, reads the kernel `ucontext_t`/`sigcontext`
register offsets, and requires a readable standard-format XSAVE image with
`FP_XSTATE_MAGIC1`, a bounded advertised extent, and the matching trailing
`FP_XSTATE_MAGIC2`. User code selectors and canonical user RIP/RSP are checked
before the saved GPR context is selected as the next frame (canonical user
addresses are limited to the 57-bit x86-64 user range). Invalid, unreadable
or multiple candidates leave the live register source selected. This layout is
the Linux x86-64 kernel signal ABI; it does not cover i386, x32, alternate
vendor kernels with a different frame layout, legacy FP-only signal frames,
or non-Linux ELF targets. FP/SIMD state is validated only as frame evidence
and is not recovered into the displayed caller register set.

Linux AArch64 signal frames are also recognized when exactly one candidate is
found within 64 KiB above the stopped SP. The selector checks EL0t PSTATE,
aligned user PC/SP, the fixed `sigcontext` fields, and a terminated, bounded
`_aarch64_ctx` record list before using the saved caller state. It restores
X0-X30, SP, PC and PSTATE, plus FPSIMD V/D aliases and FPSR/FPCR when a valid
FPSIMD record is present. ESR is exposed when present. One `extra_context` is
followed only when its pointer exactly identifies the space after the in-frame
terminator and its extent is aligned and at most 256 KiB; nested extra records
are rejected. Other extension records are skipped by their checked sizes, so
SVE/SME, GCS and newer architecture state are not included in this recovered
caller snapshot. Invalid, unreadable or ambiguous candidates leave the live
register source selected. The layouts follow the Linux
[AArch64 signal context UAPI](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/sigcontext.h)
and [signal-frame implementation](https://github.com/torvalds/linux/blob/master/arch/arm64/kernel/signal.c);
other operating systems and vendor-specific layouts are not inferred.

ARM uses DWARF R0-R15, SP=R13 and LR=R14, and requires return column 14. Unspecified caller state retains available R4-R8, R10-R11 and LR; platform-defined R9 and volatile registers require explicit rules. SP becomes CFA and PC becomes the recovered LR. The raw PC/LR retains the Thumb state bit, while FDE lookup, module translation, symbolization and local-range lookup use the code address with bit zero cleared. A32 return addresses must be word-aligned; Thumb addresses retain bit zero. This does not evaluate `.ARM.exidx`/EHABI or unwind exception-mode banked registers.


MIPS32 uses integer DWARF GPR0-GPR31, SP=GPR29, RA=GPR31, and requires return column 31. Unspecified caller state retains available S0-S7 and FP/S8 (GPR16-GPR23 and GPR30); explicit rules can recover other GPRs. GPR0 is constant zero and cannot be redefined. Classic MIPS return addresses must be word-aligned. When the caller explicitly identifies MIPS16 or microMIPS mode, bit zero is retained in `caller_pc` and GPR31 while the desktop uses the bit-cleared code address for lookup; addresses without the state bit must still be word-aligned. The default evaluator mode remains classic MIPS. `caller_pc` carries the return address separately, and the caller SP is set to CFA. FPR, HI/LO, DSP and ABI-specific signal-frame state remain unsupported.

RISC-V uses integer DWARF X0-X31, SP=X2, RA=X1, and requires return column 1. Unspecified caller state retains available RA, GP, TP, S0-S11 and constant X0; SP becomes CFA. Explicit rules can recover other integer registers. X0 cannot be redefined. Return addresses must be at least halfword-aligned. `caller_pc` carries the return address separately: DWARF column 32 is F0, so no synthetic PC entry is inserted into the register map. The UI accepts X-numbered registers, standard integer ABI aliases and FP=S0/X8. Embedded-register ABIs, RV64ILP32, unknown ELF flag extensions, and alternate signal return column 64 are unsupported. Hardware floating-point ABI flags are accepted, but CFI rules involving floating-point registers still fail.

The register numbering and ABI preservation rules follow [Arm DWARF](https://github.com/ARM-software/abi-aa/blob/main/aadwarf32/aadwarf32.rst), [AAPCS32](https://github.com/ARM-software/abi-aa/blob/main/aapcs32/aapcs32.rst), and the [RISC-V ELF psABI](https://github.com/riscv-non-isa/riscv-elf-psabi-doc). The desktop requires matching ELF machine/class/order and full-width ARM/RISC-V register snapshots. Conflicting aliases, missing SP, invalid return-code mappings, unreadable state, repeated PCs, non-increasing SP and the 128-frame bound stop walking. No new native ARM32/RISC-V backend is provided: recovery requires a target/remote session that already supplies the matching register snapshots and memory.

Each retained x86-64 recipe also carries its CIE file offset, optional personality and LSDA pointer records, and the optional LSDA encoding and its CIE file offset (including an explicit omit encoding). An `ElfEhFramePointer` records the encoding byte and its file offset, pointer field file offset and encoded byte count, decoded value, and optional direct target. For an indirect encoding, the value identifies the unresolved pointer slot and `target` remains empty: the loader never dereferences that slot or assumes that linked file bytes contain its runtime value. For a zero pointer, the value remains zero even with PC-relative encoding and `target` is empty. The encoding distinguishes indirect references from direct nulls. LSDA call-site/action tables are not parsed, language personalities are not executed, and no relocation or runtime resolution of personality/LSDA references is attempted.

Relocatable ELF `.eh_frame` sections are skipped with an explicit metadata diagnostic because their addresses require relocation application. Compressed sections, unsupported machine IDs, unknown augmentation tags, duplicate tags, indirect FDE range pointers, unsupported pointer applications/formats (including text/data/function-relative and aligned applications), malformed records or bounded payloads, and ranges outside executable bytes are also rejected with a diagnostic. `DW_EH_PE_omit` is accepted only for the LSDA encoding. Valid indirect personality/LSDA encodings remain accepted as unresolved source evidence. Rejection marks ELF metadata incomplete but does not prevent ordinary image loading or discard other ELF metadata.


ELF64 MIPS `.eh_frame` FDE ranges are accepted as bounded function-root evidence. The reader retains the raw CFI program and return-register column (MIPS DWARF register 31 is `$ra`); caller-frame evaluation is not added for MIPS64 by this change. Function-engine fingerprint v61 distinguishes the expanded root set.

ELF32 PowerPC (`EM_PPC`) and ELF64 PowerPC (`EM_PPC64`) `.eh_frame` FDE ranges now also seed functions and provide bounded ownership extents after the existing initialized executable-range validation. CFI remains raw metadata for these architectures: the loader does not evaluate PowerPC CFI or infer caller register state. Relocatable objects still require relocation application before their FDE addresses can be used.
