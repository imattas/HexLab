# PE group cursor resources

The PE resource inventory decodes `RT_GROUP_CURSOR` (type ID 12) directory
payloads with the standard six-byte group header and bounded 14-byte entries.
It retains each entry's 16-bit width/height, planes, bit count, declared byte
size, cursor resource ID, and source spans. At most 256 entries per group and
4 MiB of group-cursor directory payloads are decoded.

Each entry is linked only to a unique same-language `RT_CURSOR` resource (type
ID 1) with the matching numeric resource ID. The inventory compares the
entry's declared byte size with the linked PE resource size and marks the group
incomplete on unresolved, ambiguous, or size-mismatched links. The CLI prints
at most 256 groups and 4,096 entries.

The cursor bitmap payload remains opaque. In particular, its cursor hotspot
prefix and DIB/XOR/AND image data are not decoded or rendered. The group and
payload relationship follows Microsoft's [resource file format
description](https://learn.microsoft.com/en-us/windows/win32/menurc/resource-file-formats)
and the predefined [Win32 resource type identifiers](https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types).
