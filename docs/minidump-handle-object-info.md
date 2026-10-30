# Minidump handle object information

Version 2 `MINIDUMP_HANDLE_DESCRIPTOR_2` records can point to a linked list of
`MINIDUMP_HANDLE_OBJECT_INFORMATION` records. The loader retains each record's
`NextInfoRva`, `InfoType`, and `SizeOfInfo`, copies the following payload bytes
without interpreting their OS-specific layout, and records file offsets for
both header and payload. This keeps unknown information types available to
later analysis without assigning unsupported semantics.

The loader bounds each handle to 1,024 object-information records and the whole
dump to 65,536 such records. Retained headers and payloads share the existing
64 MiB metadata budget. Out-of-file headers or payloads, and cyclic chains,
are rejected. Cancellation is checked between records. Version 1 handle
descriptors have no object-information list.

The layout follows Microsoft's [`MINIDUMP_HANDLE_OBJECT_INFORMATION`]
structure and [`MINIDUMP_HANDLE_OBJECT_INFORMATION_TYPE`] enumeration. The
payload is intentionally opaque because its meaning can vary by object type,
Windows version, and processor architecture.

[`MINIDUMP_HANDLE_OBJECT_INFORMATION`]: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_handle_object_information
[`MINIDUMP_HANDLE_OBJECT_INFORMATION_TYPE`]: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidump_handle_object_information_type
