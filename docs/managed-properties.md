# Managed property declarations

`parse_managed_properties` reads Property (0x17), PropertyMap (0x15), optional
PropertyPtr (0x16), and property-associated MethodSemantics (0x18) metadata.
`inspect_managed_properties` applies the same reader to the bounded CLR metadata
root of a loaded PE. Neither API invokes property methods or discovers external
assemblies. Property metadata is a named collection of methods, rather than a
storage location or a guarantee about accessor behavior.

Each declaration retains its token, flags, name, owning TypeDef token/name,
signature-blob index, optional resolved signature, optional Constant default,
and accessor MethodDef/MethodSemantics tokens with Setter, Getter or Other
roles. Property rows and signature payloads retain metadata-root-relative byte
offsets and lengths. Accessor rows retain their MethodSemantics metadata offset.
These offsets are not PE file offsets or RVAs: callers must map the metadata
root before navigating to the input file.

Ownership follows PropertyMap list boundaries and the PropertyPtr permutation
when present, including unoptimized `#-` metadata. Invalid/duplicate parent or
pointer indexes, empty/out-of-order list ranges, unowned initial rows, reserved
property flags, malformed heap/table extents and inconsistent HasDefault /
Constant metadata fail closed. Accessor associations must reference an existing
MethodDef on the property's owning TypeDef. Invalid role flags, duplicate method
links and duplicate Getter/Setter roles are rejected. Repeated Other roles can
name distinct methods. Event associations are not exposed by this API.

PropertySig accepts only PROPERTY (0x08), optionally HASTHIS (0x20), followed by
the index-parameter count, non-void property type and index-parameter types.
The existing bounded managed type grammar resolves local TypeDef, TypeRef and
TypeSpec identities. Primitive, pointer/byref, array, generic-variable and
generic-instantiation forms follow that grammar. Unsupported element types,
including custom modifiers, leave a declaration with an explicit signature
diagnostic and original payload extent. Supported signatures require exact
consumption; malformed signatures fail instead of becoming partial guesses.
Getter and setter signatures are now checked against PropertySig when both
signatures use retained shapes. A getter must match HASTHIS, return the property
type, and take exactly the index parameters. A setter must match HASTHIS, return
void, and take the index parameters followed by the property type. Mismatches are
retained as invalid accessor diagnostics; custom modifiers, generic accessors,
array size/lower-bound distinctions, and other unsupported shapes are reported
as unsupported rather than treated as matches. Other-role methods remain
unvalidated. Staticness is represented only by HASTHIS, and visibility/runtime
dispatch are not inferred. A declaration without accessors is retained.
Default values preserve raw integer/IEEE bits, UTF-16 units or validated null
through the existing Constant reader; they are not executed or converted.

Limits are a 64 MiB root, 65,536 properties/maps, 250,000 MethodSemantics rows,
4,096 bytes per property name, 8 MiB combined retained property/owner names,
65,536 bytes per property or accessor signature, 16 MiB aggregate property
signature payloads and 16 MiB aggregate accessor payloads. Each PropertySig has
at most 1,024 index parameters, existing 16-level type recursion, and property
and accessor resolution each has a 100,000-node type-resolution budget. Constant and type
catalog parsing retain their own existing bounds. Allocation failures become
resource-limit errors.

`hexlab_cli project properties <project>` reports up to 128 properties, up to
16 index parameter types/accessor links per property and up to 64 UTF-16 units
per default string, with omission counts and metadata provenance. It returns
0 when every property signature decodes and every Getter/Setter signature is
validated, and 3 when property/accessor signatures are unsupported or invalid,
including rows omitted by the display cap. This status describes the supported
metadata subset, not CLI verification or runtime correctness.

The wire tables and PropertySig grammar follow ECMA-335 Partition II
§22.28, §22.34–35 and §23.2.5 in Microsoft's
[CLI metadata specification](https://download.microsoft.com/download/7/3/3/733ad403-90b2-4064-a81e-01035a7fe13c/ms%20partition%20ii.pdf).
Event declarations, custom-attribute decoding, custom-modifier interpretation,
full exceptional propagation and broader CIL metadata remain separate gaps.
