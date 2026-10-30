# CLR field and parameter marshal metadata

`parse_managed_marshal_descriptors` reads ECMA-335 `FieldMarshal` table rows
from either optimized `#~` or unoptimized `#-` metadata. Each row retains its
`FieldMarshal` token, exact `Field` or `Param` parent token, table-row offset,
`#Blob` heap index, payload offset relative to the metadata root, and the raw
`NativeType` descriptor bytes. The CLI exposes these records with
`hexlab_cli project marshaling <project.hxproj>`; payloads are shown as
hexadecimal, capped at 128 displayed bytes per row and 256 rows per command.

The parser validates the table row layout and extent, `HasFieldMarshal` tag,
nonzero/in-range parent RID, parent table bounds, unique parent ownership,
nonzero blob index, compressed blob length and heap extent. The catalog is
limited to 250,000 rows, 1 MiB per descriptor and 16 MiB total descriptor
payload. Malformed metadata and resource-limit conditions are errors.

The raw `NativeType` payload remains authoritative. A second bounded decoder
adds `decoded_scalar`, `decoded_array`, and `decoded_custom_marshaler` views;
unrecognized tags, extra trailing data, and unrecognized valid forms retain
their raw bytes with `opaque_unknown` status rather than failing the metadata
catalog. The CLI prints the decode status and only emits parsed fields for
fully consumed recognized encodings.

The recognized scalar set includes the ECMA-335 II.23.4 intrinsic numeric,
native integer, function-pointer, `LPSTR`, and `LPWSTR` forms, along with the
well-known `BSTR` string encoding. `ARRAY` accepts an intrinsic element type
and up to two compressed values for the size parameter index and element
count. A nonzero parameter index is decoded only for a Param parent; other
array forms remain opaque. Array count is descriptive only and is not used to
read memory or infer a signature.

The Microsoft `CustomMarshaler` extension is decoded only when its four
counted UTF-8 strings (GUID, unmanaged type, managed type, and cookie) fit and
consume the entire payload. The strings are retained as raw string bytes, with
null fields preserved. Unknown Microsoft extensions such as SAFEARRAY,
FIXEDARRAY, fixed strings, newer platform-specific native types, and other
array extensions remain opaque. No descriptor is executed or applied, no
custom type is resolved, and this view makes no claim about platform ABI
behavior. See [ECMA-335 II.23.4](https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
for the standard descriptor grammar and [Microsoft's UnmanagedType reference](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.unmanagedtype)
for the custom-marshaler enum and usage.

The owner-aware catalogs now attach each descriptor to its matching
`ManagedField::marshal_descriptor` or `ManagedParameter::marshal_descriptor`
after validating the Field/Param token. `project fields` prints the field's
marshal token, decode status, recognized native type, and raw payload size;
`project methods` prints the same summary under the owning parameter, including
sequence zero return parameters. The standalone `project marshaling` query
continues to expose the complete raw descriptor and provenance. A descriptor
does not change the managed signature or imply that its native representation
is safe, executable, or ABI-compatible on the current machine.
