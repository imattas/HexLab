# Minidump MemoryInfoList inventory

The Minidump parser preserves every validated `MemoryInfoList` row as
`MinidumpMetadata::memory_info`, including virtual address ranges for which the
dump contains no captured bytes. Each row retains its base, allocation base,
region size, allocation and current protection values, state, type, and the
source file offset of its 48-byte record. The stream's declared entry stride
may be larger than 48 bytes; extension bytes remain opaque.

The existing mapped-memory view still intersects these rows with captured
memory descriptors to derive effective segment permissions. `memory_info`
provides the full virtual-memory inventory independently of that intersection.
The CLI prints at most 128 rows and reports the omitted count. This is metadata
only: it does not reconstruct uncaptured bytes, infer allocation contents, or
interpret undocumented protection/state/type values.

Parsing remains bounded by the stream extent, the existing 131,072-row limit,
and the Minidump metadata budget. Address ranges must be nonempty, must not
overflow, and must not overlap after sorting. The layout follows Microsoft's
`MINIDUMP_MEMORY_INFO_LIST` and `MINIDUMP_MEMORY_INFO` definitions.
