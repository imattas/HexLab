# Mach-O indirect symbol slot bindings

After reading `LC_DYSYMTAB` and the nlist table, the loader relates entries in
the dynamic indirect-symbol table to slots in `S_SYMBOL_STUBS`,
`S_LAZY_SYMBOL_POINTERS`, `S_NON_LAZY_SYMBOL_POINTERS`, and
`S_THREAD_LOCAL_VARIABLE_POINTERS` sections. Each
`MachOIndirectSymbolBinding` records the dynamic-symbol-table command, section
ordinal, slot number and section-relative offset, indirect-table index, raw
entry, section type, and optional slot file offset. Lazy, non-lazy, and
thread-local variable pointer slot sizes use the Mach-O pointer width; stub
slots use the section's `reserved2` stride. CLI inspection prints these rows
with the aggregate completeness flag.

The section's `reserved1` value selects its first indirect-table entry. A
section is mapped only when its size divides evenly by the applicable slot
stride and its complete slot range fits in the parsed indirect table. The
loader maps slots only when exactly one `LC_DYSYMTAB` is present, because
`reserved1` does not identify which command's indirect table owns the range.
Multiple or missing dynamic-symbol-table commands leave the bindings empty
and set `indirect_symbol_bindings_complete` false.
`LOCAL` and `ABS` sentinels are preserved as distinct binding kinds. Ordinary
entries expose a nlist index only when the exact symbol-table command is
available and the index is in range. Reserved high-bit combinations remain
visible as raw entries and make `indirect_symbol_bindings_complete` false.
That flag also reports incomplete section/table bounds, missing nlist
association for ordinary entries, and the one-million-row cap.

This metadata records static slot-to-indirect-table relationships only. It
does not execute lazy binding, apply dyld rebases/binds, select a library, or
claim that a pointer's runtime contents equal the named symbol address. Other
indirect section types remain outside this mapping.
