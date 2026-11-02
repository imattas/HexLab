# Select folding and known-bit propagation

Extend typed SSA simplification for `select_if(condition, pair(yes, no))`.

- A constant one-bit condition selects its exact typed arm. The condition must be Boolean or a one-bit integer. The unselected arm is lazy and may contain a memory access, trap, or opaque expression without being evaluated.
- Identical arms collapse only when the condition is a total pure SSA bitvector, preserving the behavior of potentially faulting/effectful conditions.
- Known-bit analysis uses the selected arm when the condition is proven. With an unresolved condition, only zero/one bits common to both arms survive. An arm whose facts are unsupported contributes no known bits.
- Exact result/arm type and width validation is required. Existing work/depth limits remain authoritative.

No division, overflow, or out-of-range shift assumptions are added. Unsupported or partial expressions stay conservative.
