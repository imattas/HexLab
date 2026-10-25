# x86 ENTER stack-frame analysis

## Goal

Recover direct BP-relative local and argument slots after x86 `ENTER`, including
the allocation and nested frame-chain pushes already represented by the decoded
instruction. Normalize each slot to the stack pointer at function entry, just as
for `push`/`pop` and explicit SP arithmetic.

## Design

The analyzer consumes `ENTER`'s two decoded immediates, `stack_value_width`, and
`stack_slot_count`; it does not infer instruction size or nesting from formatted
text. The low five nesting bits determine the number of stack words consumed
(one for level zero, otherwise level plus one). The resulting SP depth after
those pushes is the new BP depth, and the unsigned allocation immediate is then
added to SP depth. BP and SP memory operands therefore share entry-SP-relative
slot coordinates.

Invalid or absent immediate metadata, a mismatch between the encoded nesting
level and decoded slot count, a missing stack width, arithmetic overflow, or a
previously unknown SP relation yields no guessed frame relation and marks the
flow unsupported. `LEAVE` clears the tracked BP relation after restoring SP.
Writing BP with `POP` also discards the old relation.

## Scope

This covers statically decoded x86-16/32/64 `ENTER` frames. It does not infer
ABI parameter types, dereference nested static-link chains, or model dynamic
stack changes. The containing stack-analysis validation guide records the
existing architecture support and its remaining limits.
