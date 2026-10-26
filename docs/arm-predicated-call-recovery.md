# ARM predicated calls in recovered control flow

Reachable analysis and function recovery retain a skipped-instruction path
whenever an ARM predicate may fail. This covers A32 condition codes and Thumb
IT predicates, including `unknown_it` only when the incoming IT state is
unresolved. Conditional or unresolved-predicate returns and traps retain their
terminal outcome plus a fallthrough edge. PC-writing instructions whose target
is not modeled retain an unsupported stop; if their predicate may fail, the
fallthrough path is still explored.

For a predicated ARM call this includes A32 conditional `BL` and a Thumb call
whose IT predicate is conditional or unknown. Both paths lead to the same next
instruction: one follows a call that eventually returns, and the other skips
the call because its predicate failed.

The call target remains a call candidate and is validated using the usual
execution-context and initialized-executable-byte checks. When the predicate
is unknown, recovery keeps both paths rather than assuming that the instruction
executes. Unconditional calls retain only the call-continuation edge.

This models the CFG alternatives without evaluating condition flags or
predicting whether a call returns. Call edges continue to mean that the callee
may be invoked; the additional `conditional_false` edge records the skipped
instruction path for downstream graph consumers. Mode-transition checks and
initialized executable target validation remain in force for resolved control
targets.
