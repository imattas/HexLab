# Imported `#pragma pack` semantics

The header importer applies packing directives in source order, before laying
out each aggregate. Supported caps are `0`, `1`, `2`, `4`, `8`, and `16`;
zero means the target's natural member alignment. `#pragma pack(n)` changes
the active cap for subsequent aggregates. `#pragma pack()` and the accepted
spelling `#pragma pack(default)` restore natural alignment. `pack(n)` changes
do not alter the saved push stack.

`#pragma pack(push[, name][, n])` saves the current cap and optionally sets a
new one. `#pragma pack(pop[, n])` restores and removes the top saved entry,
then optionally applies `n`. `#pragma pack(pop, name[, n])` removes the named
entry and entries above it, restores its saved cap, and optionally applies
`n`. A pop with no matching entry is reported as malformed instead of silently
leaving the active state uncertain. `#pragma pack(show)` adds a diagnostic to
`HeaderImportResult::diagnostics` reporting the current cap or `default`.

Pack caps affect aggregate member layout only. Effective member alignments and
the aggregate packing cap are stored on the immutable type, so type encoding
and project persistence retain the computed offsets, final size, active cap,
and any explicit member alignment. Arrays keep their element stride; the
packing cap changes placement of the array member as a whole, not the layout
of each array element.

Other pragmas, malformed argument lists, unsupported caps, unmatched pops,
and non-literal cap spellings return explicit importer errors. The importer
uses natural target alignment as the default and does not model compiler
command-line packing settings such as `/Zp` or `-fpack-struct`. The `show`
diagnostic is descriptive only and does not emit a compiler warning.
