# SSA input validation

`to_ssa` validates modeled register-output lists before assigning versions.
Call and intrinsic writes are capped at 256 registers per statement. Every
output register must have a nonzero width, and the same bank/index/width/high
byte view cannot appear twice in one output list. Intrinsic output formulas
may be omitted for opaque results; when present, they must contain exactly one
non-null expression per register output.

These checks prevent ambiguous multiple SSA definitions from being assigned to
one statement and bound work on malformed IR. They do not add architectural
register-alias canonicalization: distinct register views remain separate SSA
variables and must be normalized by the lifter when the architecture requires
write-through or zero-extension behavior.

## Register SSA verifier

`validate_register_ssa` provides a structural check for clients that consume
or persist a lifted SSA function. It rejects duplicate block identities,
CFG edges whose block ID and target address resolve to different blocks,
duplicate nonzero register definitions, missing output versions, unresolved
register uses, and uses whose definitions do not dominate them. Phi inputs must
name each reachable CFG predecessor exactly once, and the incoming value must
be available at the predecessor exit. Version zero is the implicit incoming
function value. Unreachable blocks are ignored, matching `to_ssa` renaming.

The returned summary counts reachable blocks, register definitions, uses and
phi nodes. The verifier also checks supplemental memory-partition SSA: partition
phis must cover each reachable predecessor once, partition effects must have
unique nonzero output definitions, and their input versions plus partitioned
loads must be available at the use. It checks the corresponding predecessor
values at each partition phi and requires a partitioned store to have a matching
write effect. Whole-memory SSA receives the same structural checks: stores,
calls, and writing intrinsics define unique versions; loads and effects use
defined dominating versions; memory phis cover every reachable predecessor;
and intrinsic input/output versions must agree with the declared memory effect.
No-write summarized calls may retain an identical input/output version. Type
consistency, alias inference, and canonicalization of overlapping architectural
register views remain outside the verifier. JVM evaluation-stack values are
excluded because their versions and edge transport are owned by the managed
stack-shape lifter.
