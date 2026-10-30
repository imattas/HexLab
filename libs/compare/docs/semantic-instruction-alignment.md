# Semantic instruction alignment

`diff_function_instructions_detailed` now aligns instructions using the
combined fingerprint, opcode, flow, operand signature, and effect signature.
The plain `diff_function_instructions` API continues to align by fingerprints
alone. Detailed alignment therefore avoids treating repeated normalized
fingerprints as exact anchors when their retained semantics differ.

The detailed path builds one bounded 64-bit alignment key per instruction on
each side. `FunctionInstructionDiffOptions::max_semantic_alignment_items`
limits the aggregate key count and defaults to one million. Semantic fields
are compared again when equal runs are refined, so key collisions cannot make
a changed instruction appear equal; at worst they leave a less precise
alignment. Cancellation and the existing matrix and anchor-index budgets still
apply to the resulting sequence diff.

This remains a structural comparison. It does not prove semantic equivalence,
recover moved-instruction relationships, or match split and merged blocks.
