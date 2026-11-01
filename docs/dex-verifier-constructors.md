# DEX constructor initialization flow

The bounded DEX loader verifier distinguishes initialized references from
uninitialized objects. Each `new-instance` carries its allocation instruction's
method-relative byte offset and type ID. All three `move-object` encodings copy
both facts. A constructor's incoming `this` has a separate identity; the
`java.lang.Object` constructor starts with initialized `this`.

An ordinary method call naming `<init>` must use `invoke-direct` or
`invoke-direct/range` and a void-return prototype. The loader also handles the
decoder's two one-receiver optimized `0xf0` initializer encodings. Its known
receiver must be an uninitialized object. Null, scalar, conflicting, and already initialized
receivers are rejected. The existing bounded reference-assignability walk checks
the receiver against the method owner and rejects proven contradictions. Missing
external hierarchy facts stay unresolved. The verifier permits compatible
ancestor constructor owners rather than requiring an exact allocation class or
immediate superclass match.

After argument checks succeed, the normal outgoing state initializes every
register alias of that allocation, retaining its concrete type descriptor. Two
different allocations of the same type remain distinct. For example:

```text
new-instance v0, LExample;
move-object v1, v0
invoke-direct {v1}, LExample;-><init>()V
return-object v0
```

The final return sees an initialized `v0`. Moving the return before the call,
calling the constructor twice, or passing `v0` as an ordinary object argument
before initialization is rejected. A constructor call cannot pass its receiver
as an additional uninitialized object argument.

Uninitialized references can be copied and compared for equality. Own-class
instance field receivers on uninitialized `this` remain admissible, including
field reads for Android compatibility. Field-store values still undergo normal
descriptor checks, so an uninitialized object cannot escape through a field.
Other decoded register reads reject uninitialized references, including otherwise
opaque instruction families. Conflicting register facts also cannot be consumed
by opaque operations and thereby become permissive unknowns.

Joins preserve an uninitialized identity only if both allocation and type agree.
An initialized/uninitialized join, two different allocation sites, or an
uninitialized/unknown join produces an unusable conflict. Re-executing an
allocation instruction invalidates older uninitialized aliases from that site
before recording the newly allocated object. Initializing the new object cannot
initialize an older instance from a preceding loop iteration.

Constructor-return checking uses a separate must-initialize fact, joined with
logical AND. Overwriting the incoming `this` register cannot bypass the check,
and initializing a different allocation does not satisfy it. Every reachable
return requires initialization on all incoming paths. Throwing paths may leave
without initialization. Exception handlers receive the existing pre-instruction
state, so a constructor that throws does not initialize aliases or `this` on its
exceptional edge.

Declared `<init>` methods must be non-static and return void. Declared `<clinit>`
methods must be static with prototype `()V`; ordinary explicit calls to
`<clinit>` are rejected. Initialization flow recognizes constructors by name;
the existing encoded-method direct/virtual access-flag constraints still apply.

This remains partial static verification. Unknown register inputs remain
permissive and do not prove definite assignment. Constructor resolution, access
control, recursive constructor termination, and runtime exception behavior are
not modeled. Other optimized/quickened calls without a method prototype have no
initialization transfer and cannot consume a tracked uninitialized reference.
Whole-method flow still requires complete decoding. The existing per-method/aggregate register-cell
budgets, iteration limit, cancellation checks, and bounded hierarchy walks apply;
the additional allocation identity uses one bounded 32-bit slot per register
state. New flow diagnostics include method index, code-item file offset,
instruction code-unit offset, and opcode. No public metadata or APIs change.

The semantic reference is the Android Runtime verifier's
[constructor handling and compatibility rules](https://android.googlesource.com/platform/art/+/master/runtime/verifier/method_verifier.cc)
and [register alias/constructor-return state](https://android.googlesource.com/platform/art/+/master/runtime/verifier/register_line.cc).

Validation for this change is compilation of `libs/loaders/src/dex.cpp` with
MSVC C++20 and `git diff --check`. No tests or runtime verification were run.
