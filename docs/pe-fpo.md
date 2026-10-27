# PE x86 FPO debug records

For 32-bit x86 images, the PE debug-directory reader decodes
`IMAGE_DEBUG_TYPE_FPO` payloads as 16-byte `FPO_DATA` records. Each row retains
the function RVA and byte extent, local and parameter counts in DWORD units,
prolog length, saved-register count, SEH and base-pointer flags, frame kind, and
the exact file source span. The loader requires complete records, sorted
non-overlapping ranges inside initialized executable bytes, a prolog no longer
than the function, and a clear reserved bit. Record count is bounded by the
shared PE metadata limit. FPO records on non-x86 images are rejected as
unsupported.

These rows are descriptive metadata for legacy x86 code. HexLab does not yet
use them to execute stack unwinding or to recover locals and parameters; that
requires instruction-accurate interpretation of each frame kind and prolog.
See Microsoft's [`FPO_DATA` definition](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-fpo_data)
and [PE debug-directory format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
