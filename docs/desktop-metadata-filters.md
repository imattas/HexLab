# Desktop import and export filters

The Imports and Exports pages accept space-separated, case-insensitive terms.
Every term must match for a row to remain visible. Unqualified terms search all
displayed fields. Quoted terms can contain spaces.

Imports support `address:`, `lib:` (or `library:`), `name:`, and `ordinal:`.
Exports support `address:`, `name:`, `ordinal:`, and `forwarder:`. Examples:

```text
lib:kernel32 name:"Create File"
address:0x140012000 ordinal:17
forwarder:KERNELBASE
```

The displayed import name and original imported name are both searched, so a
demangled display name does not hide a match on its source spelling. Empty
qualified values and unterminated quotes produce an invalid filter status and
no rows. An unrecognized prefix is treated as literal text, which keeps
unqualified C++ names such as `std::vector` searchable.
