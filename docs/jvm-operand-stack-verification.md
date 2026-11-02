# Bounded JVM operand-stack verification

After parsing a method's Code, exception clauses and stack maps, the classfile
loader runs a worklist analysis from the method's descriptor-derived locals and
an empty operand stack. Each reachable instruction carries an ordered vector
of logical int, float, long, double or reference stack values plus its local
slot categories. Long and double remain indivisible stack values with a
physical depth of two slots; locals use an explicit category-2 tail slot.
Reference values carry no class identity or array component type. Uninitialized
references additionally retain their `new` bytecode offset (or the distinct
`uninitializedThis` identity) across operand-stack and local movement.

The pass rejects definite stack violations with `ErrorCode::malformed` and the
method-relative bytecode offset:

- Underflow, an incorrect primitive/reference operand kind, or a physical stack
  depth exceeding `Code.max_stack`.
- Invalid category combinations for pop, pop2, dup, dup_x1, dup_x2, dup2,
  dup2_x1, dup2_x2 or swap. The shared processor stack-permutation evaluator
  supplies the legal category-1/category-2 forms.
- Different logical heights, category-2 layouts or primitive kinds reaching
  the same instruction through ordinary CFG edges.
- A reachable primitive/reference stack that disagrees with a declared
  StackMapTable or legacy StackMap frame, where that frame has no `top` entries.
- A reachable local load or `iinc` that reads an unusable local, a category or
  type mismatch, category-2 half-slot use, or disagreement with a declared
  StackMapTable/legacy StackMap local type.
- A reachable return opcode whose value category or void/non-void form does not
  match the method descriptor's declared result category.
- Use of an uninitialized reference as an ordinary operand, invocation
  receiver, field receiver, return value, monitor or array value; mismatched
  allocation identities at a stack/local merge; or a constructor returning
  before `this` has been initialized.
- Reachable normal fallthrough beyond the Code array.

Transfers cover standard non-subroutine bytecodes: constants and typed local
loads/stores/`iinc`; arrays; scalar arithmetic, shifts, conversions and comparisons; branches,
switches and returns; descriptor-driven fields and calls, including dynamic
constants and invokedynamic; allocation, casts, monitors and athrow. Arguments
are popped in reverse descriptor order, category-2 results use two slots, and
instance calls/fields consume a reference receiver. A return discards any
remaining stack after consuming its required top value, as the JVM specifies.
The entry locals are initialized from `this` (when non-static) and the method
descriptor. Stores invalidate overlapping category-2 values before writing;
local joins retain a category only when every incoming edge agrees and
otherwise degrade to unusable `top` slots; different uninitialized identities
at a local join also degrade to `top`, while different operand-stack identities
remain an error. `new` gives each allocation site a stable verifier identity.
Before repeating the same allocation site, same-identity local aliases become
`top` and the same identity may not already be on the operand stack. `aload`,
`astore`, and legal stack permutations otherwise keep that identity. A matching
`invokespecial <init>` initializes every alias on its normal edge; for an
allocation it must target the same resolved class name, and for
`uninitializedThis` it must target the current class or direct superclass.
Before that constructor call completes, the only allowed field receiver use is
`putfield` of a field owned by the current class. Constructor-call exception
edges make aliases of the attempted receiver unusable, because normal
initialization did not complete. This identity tracking detects uninitialized
local reads and primitive category mistakes without attempting general
reference assignability.

Every reachable protected instruction contributes an exceptional edge to each
covering handler using the pre-instruction locals. An exceptional edge from
`invokespecial <init>` makes aliases of that receiver unusable, while keeping
`this` uninitialized in a constructor handler. Its incoming stack is
replaced with exactly one reference, independent of the protected instruction's
ordinary stack. Handler states then participate in ordinary transfer and merge
checks, including max_stack and stack-map consistency. Reachable `new`
instructions no longer make the analysis partial by themselves. A no-StackMap
`java/lang/Object.<init>` begins with initialized `this`, as specified.
Unsupported stack-map `top` states, budgets and subroutines still make the
analysis partial. Constructor owner checks use resolved constant-pool class
names and the current class's direct superclass; catch assignability and
hierarchy-dependent local reference assignability remain unresolved.

Work is capped at eight million units per class, charging byte scans, stack
copies/comparisons, descriptor text, frame checks and handler-edge visits. At
most 1,048,576 retained stack/local entries are stored per method; instruction
states are bounded by the existing 65,535-byte Code limit. Cancellation is checked
during the pre-scan and worklist traversal. Legacy jsr/ret requires a
context-sensitive return-address model, so a method containing one keeps its
static checks but skips this pass. Exhausted budgets, unsupported evidence and
reachable stack-map `top` entries leave the class's analysis partial, with an
explicit loader diagnostic and `metadata_complete == false`; these cases do not
turn otherwise loadable input into a malformed-bytecode error.

This is a projection of the
[JVMS verification rules](https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.10.2.1),
not full bytecode verification. Different reference classes merge to the same
coarse reference category; the loader does not invent a common superclass or
prove assignment compatibility through missing hierarchy metadata. Consumers
must still reject operations that require an unavailable hierarchy proof.
Unreachable blocks are not seeded from stack maps, required frame coverage is
not established, member access, array component compatibility and runtime
linkage remain outside scope.
