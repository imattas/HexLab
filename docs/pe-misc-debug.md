# PE MISC debug records

The PE debug-directory reader recognizes `IMAGE_DEBUG_TYPE_MISC` (type 4) and
validates its 12-byte header, declared length, boolean Unicode flag, and
payload bounds. Payloads are limited to 1 MiB. For
`IMAGE_DEBUG_MISC_EXENAME` (`DataType` 1), the filename must be terminated
within the declared record. Unicode strings are decoded from UTF-16LE to UTF-8;
truncated or invalid surrogate pairs make PE metadata partial. Single-byte names
are retained byte-for-byte in the metadata string and escaped by CLI output.

Each decoded record retains the complete record source and, for the executable
name, a separate span including its terminator. Unknown MISC data types remain
available through the generic debug-directory record and do not gain a decoded
name. HexLab does not locate or bind an external DBG file based on the name.
CLI inspection displays at most 256 records.

The record is part of the PE debug directory described by Microsoft's
[PE format reference](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only).
