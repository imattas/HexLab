# Fixed-width product factoring

## Intent

Extend advanced deobfuscation with bounded distributive factoring for repeated SSA operands in sums and differences of products.

## Behavior

Recognize `x*y + x*z` as `x*(y+z)` and `x*y - x*z` as `x*(y-z)`, allowing the common factor in either multiplication operand. Require exact same-width integer types, pure versioned SSA leaves, a total supported-expression whitelist, and a 256-node cap.

## Semantic boundary

The IR `add`, `sub`, and `mul` operations are fixed-width modular bitvector operations. Preserve overflow/wraparound semantics; do not assume signed no-overflow source semantics. Avoid moving or suppressing poison/traps/effects by requiring the full tree to be total and pure. Do not factor across divisions, remainders, memory, unknown expressions, unversioned registers, floating-point values, different SSA versions, or unrelated operation trees.

## Verification

Compile the affected Windows and WSL decompiler/CLI targets with `BUILD_TESTING=OFF` where feasible. Do not run tests or CI.
