# Bounded JVM operand-stack verification

After parsing a method's Code, exception clauses and stack maps, the classfile
loader runs a worklist analysis from its empty method-entry operand stack.
Each reachable instruction carries an ordered vector of logical int, float,
long, double or reference values. Long and double remain indivisible values
with a physical depth of two slots. Reference values deliberately carry no
class identity, array component type or initialized/uninitialized identity.

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
- Reachable normal fallthrough beyond the Code array.

Transfers cover standard non-subroutine bytecodes: constants and local loads/
stores; arrays; scalar arithmetic, shifts, conversions and comparisons; branches,
switches and returns; descriptor-driven fields and calls, including dynamic
constants and invokedynamic; allocation, casts, monitors and athrow. Arguments
are popped in reverse descriptor order, category-2 results use two slots, and
instance calls/fields consume a reference receiver. A return discards any
remaining stack after consuming its required top value, as the JVM specifies.
Local loads use the opcode's stack type; the pass does not establish that a
local was initialized or actually holds that type.

Every reachable protected instruction contributes an exceptional edge to each
covering handler. Its incoming stack is replaced with exactly one reference,
independent of the protected instruction's ordinary stack. Handler states then
participate in ordinary transfer and merge checks, including max_stack and
stack-map consistency. Catch assignability, constructor aliases and exceptional
local-variable states require richer analysis and remain unresolved.

Work is capped at eight million units per class, charging byte scans, stack
copies/comparisons, descriptor text, frame checks and handler-edge visits. At
most 1,048,576 logical stack entries are retained per method; instruction states
are bounded by the existing 65,535-byte Code limit. Cancellation is checked
during the pre-scan and worklist traversal. Legacy jsr/ret requires a
context-sensitive return-address model, so a method containing one keeps its
static checks but skips this stack pass. Exhausted budgets, unsupported evidence
and reachable `top` frame entries leave the class's analysis partial, with an
explicit loader diagnostic and `metadata_complete == false`; these cases do not
turn otherwise loadable input into a malformed-bytecode error.

This is a projection of the
[JVMS verification rules](https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.10.2.1),
not full bytecode verification. Different reference classes merge to the same
coarse reference category; the loader does not invent a common superclass or
prove assignment compatibility through missing hierarchy metadata. Consumers
must still reject operations that require an unavailable hierarchy proof.
Unreachable blocks are not seeded from stack maps, required frame coverage is
not established, and local initialization, constructor initialization, member
access, array component compatibility and runtime linkage remain outside scope.
