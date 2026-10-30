# WebAssembly relocation metadata

The loader parses a bounded subset of tool-conventions `reloc.*` custom
sections into `WasmMetadata::relocation_sections`. Each section retains its
custom-section name and source offset, target module-section index, and rows
with relocation type, target offset, symbol or type index, optional signed
addend, and source offset.

Recognized relocation types are 0 through 10 and 13. Type 6 indexes the
validated type section; other supported types index the parsed `linking`
symbol table. The loader recognizes the signed 32-bit addend field for types
3, 4, 5, 8, and 9. It validates that a target section precedes the relocation
section and is code, data, or custom, and that the encoded relocation field
fits within the target section. Malformed or unsupported relocation custom
sections are ignored with an informational diagnostic while the opaque source
bytes remain available.

The parser checks the declared immediate width against the target section:
LEB/SLEB forms occupy five bytes, and I32 forms occupy four bytes. The
default aggregate cap is 1,000,000 retained relocation rows. CLI
inspection prints up to 128 section and row records. This is metadata
inspection only: relocation bytes are not rewritten, and the loader does not
validate instruction/data chunk boundaries, relocation field encodings,
linking symbol type compatibility, or relocatable-object validity. Later and
64-bit relocation types remain unsupported. Layout and entry semantics follow
the [WebAssembly tool-conventions linking document](https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md#relocation-sections).
