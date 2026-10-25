# PDB inline locals in the debugger

The desktop debugger's locals table includes PDB locals from the PE image
bound to the active workspace document. The selected stopped thread and stack
frame provide the register state, CFA, and bounded memory reads used to
evaluate each local. The Scope / origin column identifies the source record
for each row so same-named locals in separate inline scopes remain distinct.

For inline locals, the scope text shows the raw CodeView inlinee IPI index,
the module-local inline-site record offset, and the local record offset. These
are provenance identifiers, not demangled names. When the same exact module/site
has a mapped inline range at the selected PC, the scope text also shows its
source file and start line. Unsupported or missing attribution remains explicit.
For
ordinary procedure locals, the table shows the local record offset. A partial
inline-site identity is labeled as incomplete rather than inferred.

PDB defranges are active only when the selected PC falls inside their address
range and outside every encoded gap. No row is shown when no defrange is live.
If multiple defranges for one local overlap at the selected PC, the row stays
visible with Location `ambiguous` and Value `<multiple overlapping PDB live
ranges>`; the debugger does not choose one location arbitrarily. Separate
locals with matching names are retained when their record origins differ.

Supported live locations include frame-relative memory, register-relative
memory, direct register values, and supported register subfields. Evaluation
uses the selected frame's registers and memory reader, with type-sized previews
bounded by the existing debugger locals evaluator. Unsupported location forms,
missing registers or bases, unavailable type sizes, and unreadable memory are
reported in the row rather than guessed. Stack-frame source symbolization also
uses the deepest explicit inline source range, labels it `(inline)`, and declines
conflicting same-depth source locations. Source lookups examine at most 250,000
inline ranges. Local visibility still follows defranges, even when inline source
attribution is unavailable. This view does not decode PDB type names or
reconstruct a complete source-level inline call tree.
