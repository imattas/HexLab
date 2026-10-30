# Wasm extended integer global initializers

The loader accepts a bounded extended-constant subset for `i32` and `i64`
global initializers. Integer literals and reads of earlier immutable numeric
globals (imported or defined) can be combined using wrapping addition,
subtraction, multiplication, bitwise and/or/xor, shifts and rotations, the
`clz`/`ctz`/`popcnt` unary operators, `eqz`, `i32.wrap_i64`, signed/unsigned
`i64.extend_i32`, and integer sign-extension operators (`i32.extend8_s`,
`i32.extend16_s`, `i64.extend8_s`, `i64.extend16_s`, and `i64.extend32_s`).
Integer comparisons, division/remainder, floating-point operators and
reference operators in multi-instruction expressions remain unsupported.
Division and remainder are excluded because they can trap. A
typed operand stack validates every operation; the expression must end with
exactly one value matching its global's declared type. Mutable, forward,
self, out-of-range, or type-mismatched global references, underflow, extra
results and malformed literal encodings are rejected.

Multi-instruction initializers use
`WasmGlobalInitializerKind::extended_integer`. Their `instructions` vector
retains each opcode, literal bit pattern or preceding-global index, and original
instruction file offset in source order, excluding the final `end` opcode.
`expression_file_offset` retains the expression start. Existing single-literal
and single-global-get metadata keep their previous kind and `value` meaning;
the `value` field is unused for extended expressions.

Known expressions populate `evaluated_value_bits` while retaining unsigned
modulo-2^32 or modulo-2^64 target bit patterns. A dependency on an earlier
defined global uses that initializer's evaluated bits. Imported operands
initially remain unknown; after structural/body validation, the existing
caller-supplied numeric-global resolver may supply raw import bits, and the
loader recomputes dependent expressions in global declaration order. Any
unresolved operand leaves the result unresolved. Missing imports are not
replaced with zero, and no symbolic equality or algebraic simplification is
assumed. The resolver's existing type-width checks remain enforced. No host
function, module start function or imported code is executed.

Each integer initializer is limited to 256 non-`end` instructions, and the
module is limited to 1,000,000 parsed integer-initializer instructions, including
ordinary single-instruction forms. These limits also bound temporary operand
stacks and retained expression metadata. Exceeding a limit returns a resource
error. Cancellation is checked between parsed instructions and while visiting
globals during evaluation. CLI inspection/project metadata summaries identify
extended initializers, instruction counts, resolved result bits or unresolved
host dependencies within the existing 128-global display cap.

This slice applies to global initializers. Data/element offsets retain their
single `i32.const` or validated imported `global.get` subset. Float arithmetic,
integer comparisons and division/remainder, broader reference types, additional
proposal instructions, host function binding, runtime table/memory
instantiation, and decompiler use of initial global values remain unsupported.
The table/memory facts resolver only checks compatibility and reports absent
host descriptors. These records describe initial module metadata and do not
prove runtime global values after module execution.

The arithmetic operators and their constant-expression use follow the
[WebAssembly extended-constant specification](https://webassembly.github.io/extended-const/core/valid/instructions.html#constant-expressions)
and its
[proposal overview](https://github.com/WebAssembly/extended-const/blob/main/proposals/extended-const/Overview.md).
The additional non-trapping integer operations and conversions are a bounded
HexLab extension; this loader does not claim full proposal-extension support.
