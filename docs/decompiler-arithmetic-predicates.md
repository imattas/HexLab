# Arithmetic opaque-predicate proofs

The optimizer's bounded known-bit analysis now propagates facts through integer
addition and subtraction. It evaluates both as width-limited modular bit-vector
operations and carries a set of possible carry values from low bits to high
bits. A result bit is marked known only when every operand and carry
combination allowed by the input facts produces the same bit.

This proves some arithmetic opaque branches without enumerating every input
value. For example, if `x` is an integer, the low eight bits of
`(x & 0xff) + 0x100` are still exactly the low eight bits of `x & 0xff`, while
bit 8 is known to be one. A comparison against the original masked value can
therefore be rejected as always unequal. The proof also composes with the
existing bitwise, fixed shift, sign/zero extension, and comparison transfer
rules. When a branch predicate is proven, `simplify_constants` selects the
edge and removes blocks made unreachable by that edge.

The arithmetic transfer is conservative: it assumes no signed overflow rules,
uses only the expression's declared bit width, and over-approximates
possibilities between bits. Correlation between two uses of the same unknown
value may be lost, which can prevent a proof but cannot create one. Unsupported
operators, malformed types, or missing operands provide no facts. Existing
expression depth and shared proof-work budgets still bound analysis; exceeding
a budget leaves the branch unchanged.

This pass does not remove calls or reconstruct a control-flow-flattened state
machine. It only prunes a branch when the local bit-vector facts prove its
predicate constant.
