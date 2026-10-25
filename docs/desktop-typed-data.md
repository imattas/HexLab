# Desktop typed data view

The Bytes page pairs the raw byte table with a typed-data pane. In a writable project, **Assign type at cursor...** applies any complete project type at the selected mapped address through the normal project command/history path. This also works for structures, unions, and fixed-size arrays. The Types & Symbols page can still be used to define or import types and inspect existing assignments.

When the cursor is at an assigned object, the typed pane displays its scalar members and array elements. When the cursor is inside an assigned object, the pane finds the smallest containing assignment and shows each row's object-relative offset. Activating a row navigates to that field or element in the shared workspace. Integer, boolean, pointer, enumeration, and 32-/64-bit floating values use the image address space's byte order. Pointer values are displayed but never dereferenced.

The preview validates fixed type sizes and member/element bounds before reading. It reads at most 64 KiB, emits at most 512 rows, expands at most 128 elements per array and stops recursive expansion at depth 6. Incomplete layouts, unresolved virtual bases, ambiguous overlapping assignments, and unsupported scalar widths are labeled explicitly. Raw documents and unmapped file offsets retain the ordinary bytes view; assigning a type requires a mapped address in a writable project.
