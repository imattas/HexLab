# Itanium ABI template argument packs

The bounded Itanium C++ name parser now renders the nested template argument
sequence form `J <template-arg>* E`. Elements use the parser's existing type,
integral literal, and expression argument forms, and a pack can contain another
pack. The display form is `pack{...}` so the pack boundary remains visible
instead of flattening its members into neighboring template arguments.

Pack nesting is charged to the existing demangler depth limit. Each pack is
limited by the configured component budget, and rendered output is checked
against the configured output byte limit. Missing terminators and truncated
elements are malformed; unsupported element grammar remains unsupported. The
parser does not infer values or instantiate pack expansions in function and
member types.
