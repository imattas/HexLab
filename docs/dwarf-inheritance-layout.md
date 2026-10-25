# DWARF non-virtual base-class layout

The DWARF importer preserves a non-virtual `DW_TAG_inheritance` entry as a
nested aggregate member when the entry has a resolvable base type and a
constant `DW_AT_data_member_location`. The synthetic member name is
`$base$<type-name>`; repeated base types receive a numeric suffix. Its type
and byte offset keep the base subobject's layout available to type inspection
and downstream analysis without flattening or duplicating its members.

The importer currently skips virtual inheritance and base entries whose
location is absent. It does not preserve C++ access control or distinguish a
base subobject from an ordinary nested member in the shared type model. Dynamic
base offsets and empty-base overlap layouts are not inferred. Existing
`DW_TAG_member` and bitfield handling remains unchanged.
