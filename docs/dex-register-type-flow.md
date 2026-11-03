# DEX register category flow

The DEX loader runs a bounded worklist over each completely decoded method's
normal control flow. Parameter descriptors seed entry registers. Existing
instruction checks consume register categories for moves, arrays, fields,
invokes, arithmetic, conversions, comparisons, branches, and returns.

Method-entry local registers start as unassigned; only incoming parameter words
are initialized. A reachable instruction read of an unassigned register is
rejected, and a join of an unassigned path with any assigned path becomes an
unusable conflict. A decoded write whose result category is not modeled instead
produces an assigned-but-unknown value, preserving the partial verifier's
conservative type behavior without treating a missing definition as a value.

The category lattice distinguishes a literal zero from an unknown value.
Zero admits integer, float-bit-pattern, and null-reference interpretations;
nonzero 32-bit constants admit integer or float-bit-pattern interpretations.
At joins, a constant and a compatible typed value retain the typed category.
For example, null on one branch and an object on the other produce a reference,
while a raw scalar constant and an integer parameter produce an integer.
Integer and float categories, or nonzero scalar and reference categories, still
produce an unusable conflict. Generic wide constant halves similarly join with
matching long or double halves without losing the typed category.

An invoke with a validated prototype now transfers its exact return category
through its adjacent `move-result`, `move-result-wide`, or `move-result-object`.
The earlier structural pass still enforces adjacency, result variant, and the
absence of branch/handler entries into `move-result`. Long and double results
remain distinct, as do integer and float results; later arithmetic, descriptor,
and return checks can reject incompatible uses. Filled-array results retain
the existing reference category. Optimized calls without a prototype retain
the existing unknown or generic-wide fallback.

Wide values occupy adjacent low/high slots. Every decoded write invalidates an
untouched neighboring half of an existing wide value. For example, writing an
integer into `v1` after defining a long in `v0:v1` makes the old `v0` unusable
until redefined. Both slots of a wide destination are treated together, and all
sources are read from the instruction's incoming state, including overlapping
`move-wide`. Consumers requiring either kind of wide value check that both
halves admit the same long/double interpretation.

This remains partial category validation. Assigned-but-unknown facts are
permissive and do not prove a value's type. Unsupported writes erase their own
category facts. Throwing instructions propagate their incoming register state to covered
handlers, before normal register writes or constructor initialization complete.
Known reference identities are
checked for assignability at ordinary invoke receivers and instance field
receivers using the class definitions and array rules present in this DEX.
Thrown values with known non-null types must also be assignable to
`Ljava/lang/Throwable;`; literal null and unknown or unresolved reference types
remain conservative.
Before flow begins, a bounded class-data index records in-image class, field,
and method access flags independent of class-definition order. Standard field
opcodes are checked against the resolved static/instance field declaration.
Optimized volatile field opcodes (`0xe3`–`0xeb`) also receive descriptor-
driven transfers: ordinary forms require a single-word primitive, the object
form requires a reference, and wide forms require `J` or `D`. When an in-image
field declaration resolves, the verifier also requires `ACC_VOLATILE`, the
encoded static/instance form, and applicable access checks. Instance receivers
are checked against the symbolic field owner when their type is known. A
throwing volatile access sends its incoming state to covered handlers before
the normal destination write. Unresolved external declarations remain
conservative; quick field offsets (`0xf2`–`0xf7`) still have no descriptor or
owner proof.
Field and method declaration lookup follows in-image superclasses and
interfaces using exact name/type or name/prototype signatures. Resolved members
are checked against public/private/protected/package visibility; both the
symbolic reference owner and resolved declaring class must be accessible.
Method invoke opcodes
are checked against in-image method staticness and class/interface owner kind;
`invoke-super` must name a strict in-image superclass or implemented interface.
DEX 037+ permits interface `invoke-super` and interface static/private-direct
targets when their metadata proves the permitted kind; earlier versions retain
class-owner restrictions for those invoke forms. In-image `invoke-direct`
owners must be the current class or a superclass, and non-constructor special
names are rejected.
The invoke-kind and special-name constraints follow the Android
[Dalvik bytecode instruction reference](https://source.android.com/docs/core/runtime/dalvik-bytecode)
and [runtime verification constraints](https://source.android.com/docs/core/runtime/constraints).
Cross-package protected instance access also requires a known receiver type to
be assignable to the accessing class; unresolved receiver identity remains
conservative. Interface `invoke-super` remains available for a known implemented
interface default method.
Checks preserve method index, code-item offset, instruction code-unit offset,
and member index when reporting malformed references.

The declaration index is bounded by the existing DEX item limits and retains
only identifier-indexed access flags. Member lookup visits at most 4,096 types
per reference and one million aggregate hierarchy steps; a capped or incomplete
lookup remains unresolved. It does not infer member declarations through
external classpaths or optimized/quickened references. A field or method
identifier whose in-image declaration cannot be established remains
unresolved. Access checks use the encoded identifier owner and do not implement
runtime-specific nestmate access, hidden-API policy, or optimized dispatch.
When two known reference types meet at a control-flow join, the verifier keeps
a common in-image supertype when a hierarchy walk of at most 4,096 queued and
visited types can establish one.
This preserves useful facts for later receiver, argument, field-store, and
return checks. If the hierarchy is incomplete or the bounded walk cannot find
a common type, the joined identity becomes unknown and remains permissive.
External or incomplete hierarchy paths remain unresolved and are accepted
conservatively; they do not establish assignability. Path-dependent null
refinement remains unmodeled. Known array
components are checked as described in `dex-verifier-array-components.md`;
allocation identities and constructor initialization are checked as described in
`dex-verifier-constructors.md`. A successful load is not a complete Dalvik
verification certificate.

An instance-field receiver rejected by a known hierarchy contradiction reports
the method identifier-table index, code-item file offset, method-relative
instruction code-unit offset, and field identifier-table index. This provenance
identifies the exact checked use while keeping the public loader error model
unchanged.

The existing bounds remain: at most one million instruction/register cells per
method and eight million per load, cancellation checks in the worklist, and a
bounded iteration count. Incomplete decoder coverage skips the whole-method
flow pass instead of inventing instruction boundaries.

Build the implementation with `cmake --build <build-dir> --config Debug --target
hexlab_loaders` using a build directory configured for this checkout.
