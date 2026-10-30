# CLR local variable signatures

The managed metadata loader exposes ECMA-335 `LocalVarSig` decoding through
`decode_managed_local_signature` and enumerates supported rows in the
`StandAloneSig` table with `parse_managed_local_signatures`. Results use the
original `0x11xxxxxx` metadata token so callers can associate a method body's
`local_signature_token` with its local types. Each entry retains its parsed
type tree and the `pinned` marker. TypeDef, TypeRef, and TypeSpec identities
are resolved through the assembly metadata catalog when parsing the root.

The decoder validates the calling convention, compressed local count, type
grammar, and complete blob consumption. A signature is capped at 4,096 locals;
metadata roots are capped at 64 MiB and type resolution has a bounded node
budget. Custom modifiers in local types and other unsupported signature
elements are not interpreted. The API reports metadata shape only; it does
not infer stack values or runtime GC behavior.
