# Relocation-aware switch table recovery

Switch-table analysis has an overload that receives the loaded image metadata. Production function recovery reuses its existing relocation resolver; CLI and desktop queries create a bounded resolver for their source image. The legacy metadata-free overload remains for synthetic or manually constructed callers.

For file-backed 4-byte and 8-byte table slots, recovery first asks the shared resolver whether an exact relocation owns the slot. ELF absolute or PC-relative data relocations and supported Mach-O data relocations may provide the target address. Mach-O classic or chained dyld rebases may also provide preferred-image targets. A slot associated with an unresolved, overlapping, authenticated, non-pointer, or runtime-binding fixup never falls back to its raw encoded bytes. An unassociated slot continues through the existing absolute-pointer or signed-table-offset decoding.

Instruction-derived table bases can use exact supported operand relocations for x86 absolute/RIP-relative indexed tables, x86-64 `LEA` table bases, and AArch64 `ADRP`/`ADD` patterns. Relocation-backed table cases still pass executable file-backed instruction decoding and architecture/mode checks. Case scans remain capped at 4096 entries, and resolver lookup retains its own bounded work and match limits.

For ELF64 little-endian AArch64 relocatable objects, the signed-offset switch recognizer can also derive an otherwise unresolved `ADRP`/`ADD` table base from an exact paired `R_AARCH64_ADR_PREL_PG_HI21` and `R_AARCH64_ADD_ABS_LO12_NC` relocation. Both rows must be explicit-addend relocations to the same defined local symbol, with identical addends, exact instruction places and fields, and matching target sections. Ambiguous, partial, malformed, unsupported, or mismatched pairs fail closed. The resulting base is still required to address a readable file-backed table, and each signed 32-bit entry must resolve to a file-backed executable instruction in the dispatch context. The exact pair also supports the contiguous form whose signed table entries use a separate `ADR` code base. It does not infer arbitrary register values, resolve an unsupported `ADR` code-base relocation, or support linked ELF images through this special pair path.

Each recovered case records whether its target came from encoded bytes, an ELF relocation, a Mach-O relocation, or a Mach-O dyld rebase. Relocation record indexes and classic/chained dyld row indexes are preserved in the API and emitted by the CLI `switches` JSON output.

The x86-64 unsigned dword base-relative form accepts an exact supported
RIP-relative LEA operand relocation when it establishes the register base.
`table_base_source` is `operand_relocation`, and the base instruction's row
indexes are retained separately from per-case metadata. `base_definition`
identifies that LEA and `selector_use` identifies the indexed MOV. The table
address is the checked base plus the constant load displacement; the target
base remains separately visible. A relocation on that displacement, a dyld
base fixup, or a relocation/fixup-associated table slot declines recovery or
ends its verified prefix. A relocation resolver's final symbolic address does
not establish the unsigned stored-offset equation, so this form never uses
such an address directly or falls back to its raw slot bytes.

The analyzer does not apply runtime bindings, authenticated pointers, unsupported relocation equations, or runtime process slides. TBB/TBH byte/halfword offsets continue using their architectural PC-relative encoding. Table-base and target discovery remain limited to the existing recognized instruction patterns; arbitrary register-value propagation is not implied.
