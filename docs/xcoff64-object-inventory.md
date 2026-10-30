# XCOFF64 object inventory

`inspect_xcoff64_object` reads bounded big-endian XCOFF64 relocatable-object
metadata. It retains section names, physical and virtual addresses, sizes,
file offsets, relocation and line-number counts, section flags, and ordinary
section relocation rows. Ordinary relocation rows retain their virtual address,
symbol-table slot, raw size/type bytes, and source offset. The parser checks
section and table extents, symbol-slot bounds, relocation address containment,
ascending relocation order, primary-symbol references (auxiliary slots are
rejected), and configured metadata/count limits. Primary symbols retain their
slot, value, section and storage class. Names are decoded for C_EXT, C_HIDEXT,
C_WEAKEXT and C_STAT; debugging symbol names are not interpreted. The `F_EXEC`
file-header flag is rejected; this API is limited to relocatable objects.

Ordinary section relocations use the XCOFF64 14-byte record. The `.loader`
section uses distinct 16-byte runtime relocation records; this inventory
validates their extent and count but leaves them undecoded. It also does not
decode line-number rows or full auxiliary-record details, apply relocation
semantics, resolve imports, or link XCOFF objects. The file flags are read at
offset 18, independently of the symbol count at offset 20. Both the inspector
and the archive symbol summary reject F_EXEC images.

`hexlab_cli archive link-audit <archive> --root-object <XCOFF64>` now selects
members to a fixed point using the existing strong symbol summary, then audits
the root and selected objects. Each ordinary relocation reports its section,
address, raw type and recognized type name, field bit count, signedness, binder
instruction-modification flag, target symbol slot/name/section/class and symbol
resolution category. R_POS, R_NEG, R_REL, R_TOC, R_GL, R_TCL, R_BA, R_BR, R_RL,
R_RLA, R_REF, R_TRL, R_TRLA, R_RBA, R_RBR, the six TLS types (0x20–0x25),
R_TOCU and R_TOCL are named. Other types remain explicit unsupported rows with
their raw numeric type. Recognition only classifies a row; every row reports
`applied=false`.

Object-local definitions and absolute symbols are distinguished from external
references. A strong undefined C_EXT reference is matched by name against strong
concrete definitions in the selected objects, with unique, missing and multiple
providers distinguished. Common or weak providers and special symbol classes
remain deferred. Duplicate strong definitions are also reported separately.
The final AUX_CSECT row, when present, supplies the csect type and storage
mapping class; XTY_CM common csects remain deferred even with a positive section
number. This is a symbol-level audit: full auxiliary csect information, TOC
placement, TLS, weak/common binder policy, csect garbage collection, instruction rewriting,
field coverage, addends, arithmetic and overflow are not validated. In
particular, naming a provider does not establish that a relocation can be
applied. Loader sections are explicitly unsupported, even when their relocation
count is zero; their separate 16-byte relocation encoding stays undecoded.
Objects marked F_RELFLG explicitly report stripped relocation information and
unknown completeness.

The selected-object audit is bounded to 4096 objects, 256 MiB aggregate source
bytes, one million symbol slots and one million relocation rows, in addition
to per-object limits. Aggregate decoded names are also limited to 256 MiB.
Decoded names share the per-object metadata-byte budget and are
limited to 4096 bytes each. The archive selection scan retains its existing
limits. The audit returns command success when it completes its report, even
with unresolved or unsupported rows; its summary always states
`applied=0 output=none link-readiness=not-established`. `archive link` and
`link-exec` still reject XCOFF64 without writing output.

The record sizes and field offsets follow IBM's [AIX XCOFF Object File
Format](https://www.ibm.com/docs/en/aix/7.3.0?topic=formats-xcoff-object-file-format).
