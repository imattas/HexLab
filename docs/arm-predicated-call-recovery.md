# ARM predicated calls in recovered control flow

Function recovery retains the ordinary call continuation and also records the
fallthrough path for a predicated ARM call. This covers A32 conditional `BL`
and a Thumb call whose IT predicate is conditional or unknown. Both paths lead
to the same next instruction: one follows a call that eventually returns, and
the other skips the call because its predicate failed.

The call target remains a call candidate and is validated using the usual
execution-context and initialized-executable-byte checks. When the predicate
is unknown, recovery keeps both paths rather than assuming that the call
executes. Unconditional calls retain only the call-continuation edge.

This models the CFG alternatives without evaluating condition flags or
predicting whether a call returns. Call edges continue to mean that the callee
may be invoked; the additional `conditional_false` edge records the skipped
call path for downstream graph consumers.
