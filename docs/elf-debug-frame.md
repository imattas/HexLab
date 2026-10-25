# ELF `.debug_frame` CFI fallback

The ELF loader previously ignored `.debug_frame`, leaving debug-only unwind
programs unavailable when `.eh_frame` was absent. It now reads bounded,
uncompressed `.debug_frame` sections in linked ET_EXEC/ET_DYN images and uses
their validated FDEs for function-root evidence and caller-frame fallback.
No relocation application or external debug companion lookup is introduced.

The dedicated parser supports DWARF32 and DWARF64 initial lengths and CIE/FDE
identifiers, in either ELF byte order. DWARF offset width is independent of the
ELF class. It indexes all records and CIEs before resolving FDEs, so forward
CIE references work. A `.debug_frame` FDE's CIE pointer is an absolute section
offset to the CIE record start; it is never interpreted as the `.eh_frame`
backward pointer. Width-specific all-ones identifiers distinguish CIEs.
References into record bodies, outside the section or to FDEs fail.

CIE versions 1, 3 and 4 are accepted only with an empty augmentation string.
Version 4 must declare the ELF class's four/eight-byte address size and a zero
segment-selector size. Older versions use that address size implicitly.
Record starts and total extents must be aligned to the target address size.
Code alignment must be nonzero. Reserved initial-length forms, truncated
fixed/LEB operands, LEB overflow and nonzero bytes after trailing zero padding
fail explicitly. The parser accepts a zero-only trailing padding region.

FDE initial location and range use native-width absolute target addresses.
Thumb state bits are normalized for code lookup. Ranges must be nonempty,
fit the target address width and have a representable exclusive end. Every
byte must belong to initialized executable image segments. The reader permits
the normal non-allocated debug section; its records do not need runtime
mapping. A section's roots and recipes publish together only after all records
have passed structural validation.

Each source section is limited by the shared 64 MiB ELF metadata budget and
65,536 frame records. Retained live recipes also enforce the combined 1 MiB
CIE/FDE instruction limit. Indexes, retained programs and range/recipe rows
consume that shared budget. Cancellation is checked during record/CIE/FDE
iteration, executable-range validation and long padding scans.

`ElfCfiSectionKind` identifies `.eh_frame` versus `.debug_frame` in
`ElfUnwindRange`, `ElfEhFrameFunction` and `ElfUnwindResult`. The existing
`ElfMetadata::eh_frame_functions` name remains for compatibility and stores
both formats. CIE and FDE file offsets, record extents and section indexes
remain attached to accepted recipes and root evidence.

Runtime evaluation first selects an accepted `.eh_frame` FDE covering the PC;
only its absence enables `.debug_frame` fallback. Duplicate/overlapping FDEs
within the selected source remain malformed. An unsupported selected runtime
recipe never causes a speculative retry using the other source. An unrelated
malformed/unsupported section emits the existing incomplete-metadata warning
while accepted independent sections remain available. Cancellation and budget
exhaustion stop further discovery.

Live architecture/rule support is unchanged: x86-64/AArch64 use the existing
little-endian bridge; ARM32/Thumb and RV32/RV64 use their integer-only evaluator
with native word widths and either byte order. i386 and MIPS32 retain validated
root ranges without gaining caller evaluation. See
[ELF CFI support](elf-dwarf-unwind.md) for exact instructions and register sets.
This change does not add `DW_CFA_set_loc`, new expressions, signal-frame rules
or additional register banks.

Unsupported forms include ET_REL records requiring relocations, compressed or
NOBITS sections, `.zdebug_frame`, nonempty augmentations, nonzero segment
selectors, mismatched CIE address sizes and other machines. The format rules
follow sections 6.4 and 7.4 of the
[DWARF v5 standard](https://dwarfstd.org/doc/DWARF5.pdf).

Source review only; no tests or builds were run for this slice. Reconfigure
and build `hexlab_loaders`, then CLI/desktop consumers serially. The source-kind
fields change public ELF metadata/result layouts, so consumers must rebuild.
