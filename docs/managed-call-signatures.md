# Managed method signatures

Managed method inspection decodes bounded ECMA-335 method signature blobs for
`MethodDef`, method-shaped `MemberRef`, and method-shaped `StandAloneSig` tokens.
Stand-alone local-variable signatures are skipped; method call-site signatures
are stored under their `0x11` metadata tokens. The resulting token map travels
with each `ManagedMethodAnalysis`, so `decompile_managed_method(analysis)` can
lift common `call`, `callvirt`, `newobj`, and `calli` instructions without a
caller-built signature map. An explicitly provided map overrides metadata
resolution.

The method-definition decoder supports default and vararg calling conventions;
the call-site decoder additionally accepts unmanaged C, stdcall, thiscall,
fastcall, and unmanaged signatures when their stack shape is expressed by the
signature blob. Both retain generic arity,
`HASTHIS`/`EXPLICITTHIS` flags, sentinels in vararg parameter lists, and
parameter/return element types: primitives, string, object, typed reference,
native integers, class/value type tokens, pointer, byref, single- and
multidimensional arrays, generic variables, and generic instantiations. It
extracts the parameter count, instance semantics, and whether the return is
non-void. A `newobj` consumes only declared parameters and produces an object
value. The decompilation result carries declaring-type and method generic
parameter records from the method catalog; the stack model does not substitute
their concrete types.

`calli` consumes the function pointer followed by the signature's declared
arguments, emits an indirect-call intrinsic, and pushes a result when the
signature is non-void. The CLI `project methods` output shows the resolved
stand-alone signature token and its parameter/return shape. This does not
resolve the target function pointer or model platform-specific unmanaged ABI
register and stack placement. Unsupported stand-alone call-site signatures are
left unresolved so they do not prevent inspection of unrelated methods in the
same assembly. Custom-modifier and other unlisted signature forms remain
explicitly unsupported. Types are represented only by stack effects here;
generic substitutions are not performed. Parsed signature type nodes retain
their original coded indexes and resolved metadata tokens/names across TypeDef,
TypeRef, and TypeSpec. TypeRef AssemblyRef/ModuleRef scopes remain explicitly
unresolved; TypeSpec chains are bounded and cycles are rejected. Malformed compressed
integers, truncated blobs, invalid calling-convention flags, invalid sentinels,
and trailing bytes are rejected. The parser does not guess stack effects for
unresolved tokens; decompilation reports those calls unsupported.

The implementation applies limits of 4,096 parameters and 16 nested pointer or
byref element wrappers. Generic arity is bounded at 1,024. TypeSpec owner
instantiations are followed through resolved TypeSpec-to-TypeSpec constructor
chains under the same 16-level nesting bound, so closed `VAR` substitutions
reach CIL call typing even when the owning TypeSpec is indirect. Open generic
variables with no supplied owner or MethodSpec argument remain unknown. Cycles,
invalid local generic arities, and missing or ambiguous metadata identities do
not produce guessed substitutions.

Field signatures use the same bounded type-node decoder through
`decode_managed_field_signature`, which requires the `FIELD` calling-convention
byte and exactly one type. `parse_managed_fields` resolves coded type tokens
against the assembly's TypeDef/TypeRef/TypeSpec catalog and retains unsupported
field forms with a diagnostic. The CLI exposes this metadata through
`project fields`; type display is descriptive and does not perform generic
substitution or resolve external assemblies.

For `GENERICINST` nodes whose constructor resolves to a local `TypeDef`, the
catalog now checks the supplied argument count against that type's ordered,
zero-based `GenericParam` rows. A mismatch preserves the original metadata token and
arguments for inspection, but marks the instantiation invalid for typed CIL
propagation: call results and `newobj` values remain unknown while the exact
declared stack effect is retained. External `TypeRef` arity is not inferred
from names or companion assemblies; those instantiations remain unresolved
rather than being guessed.
