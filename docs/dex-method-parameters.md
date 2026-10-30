# DEX MethodParameters annotation metadata

The DEX loader derives parameter names and access flags from the
`dalvik.annotation.MethodParameters` method annotation while retaining the
original generic annotation graph. Each derived row is keyed by method ID and
zero-based formal parameter index. The receiver is not included. A null name
is retained as unnamed; a string name resolves through the shared DEX string
catalog. Separate source offsets identify the encoded name and flag values.

The `names` and `accessFlags` arrays must both be present and have the same
length as the method prototype's parameter list. Name entries must be strings
or null; flags must be encoded 32-bit integers containing only `final`
(`0x0010`), `synthetic` (`0x1000`), or `mandated` (`0x8000`). Empty names and
names containing `.`, `;`, `[`, or `/` are rejected. Unknown annotation
elements remain available in the generic annotation tree and are ignored by
this derived view.

The file and project CLI metadata views print at most 256 derived rows with
resolved names, raw flags, and source offsets. Debug-info parameter names
remain a separate source; this metadata does not replace or merge with them.
It does not infer parameter registers, receiver assignments, or Java source
types.

The annotation parser's 250,000 value-node, 64 MiB annotation-model and
64-level nesting bounds also cover these arrays. Derived rows add at most one
million records and remain charged to the same 64 MiB model budget. Parameter
array counts are validated against the method prototype before publication.

The layout and restrictions follow AOSP's [DEX format documentation for
`dalvik.annotation.MethodParameters`](https://source.android.com/docs/core/runtime/dex-format#dalvikannotationmethodparameters).
