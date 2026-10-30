# Aggregate member lookup by byte offset

`Type::members_covering_offset(byte_offset)` provides a bounded query over a
complete structure or union's stored physical-member metadata. It returns the
indices into `Type::members()` for every member whose byte storage contains the
requested offset. The API deliberately returns all matches: a union may expose
several alternatives at offset zero, and distinct bitfields can share one
allocation unit. Callers must retain the selected `TypePtr` while using the
indices so that the immutable member vector remains alive.

Incomplete/non-aggregate types return an empty result. Members with deferred
named-reference extents, flexible arrays, virtual bases, and zero-width
bitfield barriers do not claim a fixed byte range and are skipped. For a
bitfield with nonzero width, the result represents its storage unit; callers
can inspect `bit_offset` and `bit_width` to distinguish individual bits. The
query does not resolve symbolic references or infer layout from an ABI; it
answers against the aggregate's stored byte offsets and known member sizes.
