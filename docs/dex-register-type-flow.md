# DEX register category flow

The DEX loader runs a bounded worklist over each completely decoded method's
normal control flow. Parameter descriptors seed entry registers. Existing
instruction checks consume register categories for moves, arrays, fields,
invokes, arithmetic, conversions, comparisons, branches, and returns.

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

This remains partial category validation. Unknown facts are permissive and do
not prove definite assignment. Unsupported writes erase their own category
facts. Handlers start with unknown registers because instruction-level
exceptional type propagation is not implemented. Known reference identities are
checked for assignability at ordinary invoke receivers and instance field
receivers using the class definitions and array rules present in this DEX.
External or incomplete hierarchy paths remain unresolved and are accepted
conservatively; they do not establish assignability. Array element descriptors,
constructor initialization, and path-dependent null refinement are not
modeled. A successful load is not a complete Dalvik verification certificate.

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
