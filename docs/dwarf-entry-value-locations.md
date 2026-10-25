# DWARF entry-value locations

The bounded DWARF v2–v5 location-expression decoder accepts
`DW_OP_entry_value` (`0xa3`). It decodes the ULEB128 block length and nested
expression, retaining the nested operations in the imported location model.
The decoder shares one 4096-operation budget across all nested blocks, caps an
entry block at 64 KiB, and limits nesting to 16 levels. Truncated blocks remain
malformed; work beyond a configured structural bound returns a resource-limit
error.

At evaluation time, callers provide
`LocationEvaluationContext::read_entry_register` and
`LocationEvaluationContext::read_entry_memory` separately from the current-state
readers. Nested dereferences use only `read_entry_memory`; the current memory
reader is never substituted. A nested expression that finishes as a memory
location reads one scalar using the target address size (1, 2, 4, or 8 bytes).
A register location is materialized through the entry-register reader, and an
expression ending in `DW_OP_stack_value` supplies its scalar directly.

Frame-base and CFA values are cleared while evaluating an entry expression;
there is no entry-frame/CFA callback yet, so nested operations that require
those values return `unsupported`. Register numbers and values are not
invented. Recursive evaluation shares a 65,536 executed-operation budget, a
4,096 memory-read budget, and a 64-entry stack limit. The final memory-location
read uses address size because the scalar evaluator has no type-width input;
callers that need a different width can use an explicit nested dereference-size
operation where the DWARF expression provides one.

The operand and evaluation model follow the
[DWARF Version 5 standard, section 2.5.1.7](https://dwarfstd.org/doc/DWARF5.pdf)
and its [entry-value clarification](https://dwarfstd.org/errata-dwarf5.html).
