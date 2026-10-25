# Interprocedural typing across calling conventions

`recover_interprocedural_types` matches a direct call only when its target is
one of the supplied lifted function entries. For calls whose caller and callee
use different ABI descriptions over the same register file, the callee's
argument map now selects the physical registers captured at the call. Concrete
formal parameter types can flow back to those SSA values as type evidence,
unless existing local type facts conflict. These facts can then identify
forwarded caller parameters and participate in the ordinary unanimous caller
consensus for the target function.

The callee's ABI also selects a modeled scalar, pointer, floating, or vector
return register. Calls made from one function to targets with different
conventions invalidate the union of those targets' caller-saved registers.
This prevents a value from being treated as preserved when one of the targets
can clobber it; it may also discard facts that a particular target preserves.

The analysis checks pointer width and the set of register banks before allowing
cross-ABI propagation. It still requires an exact target and a supplied callee
body or prototype. Stack arguments can cross conventions when the callee slot
has a known entry-relative offset and a backward scan proves a register-valued
store of matching width/class at the corresponding outgoing stack location.
Unknown memory effects, calls, overlapping stores, and unproven stack aliases
stop the proof. Indirect calls are usable only when their exact target is
resolved through bounded constant/copy/agreeing-phi analysis. Aggregate return
conventions and calls across different register files remain outside this pass.
All inferred types remain heuristic analysis results and do not replace
explicit prototype assignments.
