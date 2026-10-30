# Managed custom-attribute metadata

`parse_managed_custom_attributes` in `hexlab/loaders/managed.hpp` enumerates bounded ECMA-335 CustomAttribute rows from a metadata root. Each result retains its CustomAttribute token, resolved parent token, constructor token, `#Blob` heap index, and metadata-root-relative row offset.

The parser validates the HasCustomAttribute tag and row range, permits only MethodDef and MemberRef constructor tags and checks their row ranges, bounds each blob read, and requires the serialized custom-attribute prolog `0x0001`. It removes that two-byte prolog from `serialized_value` while preserving the rest of the payload byte-for-byte. Limits are 250,000 rows, 4 MiB per value, and 64 MiB total values, over a metadata root no larger than 64 MiB.

The payload remains opaque. The parser does not resolve constructor signatures, decode fixed or named arguments, interpret enum or array element types, or instantiate attributes. Malformed parent, constructor, row layout, blob extent, or prolog data is reported rather than partially interpreted.
