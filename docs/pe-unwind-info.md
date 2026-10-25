# AMD64 PE unwind metadata

The PE exception-directory reader decodes x64 runtime-function entries and their version 1 `UNWIND_INFO`. Each runtime range retains source provenance and a normalized prolog-operation list. The decoder covers `PUSH_NONVOL`, both `ALLOC_LARGE` encodings, `ALLOC_SMALL`, `SET_FPREG`, `SAVE_NONVOL` and `_FAR`, `SAVE_XMM128` and `_FAR`, and `PUSH_MACHFRAME`. Handler records and chained runtime-function records are retained, and chained metadata is decoded recursively with cycle and depth checks.

The exception table is committed as one metadata batch: malformed bounds, flags, operation slots, handler references, language payload records, or chains reject the table rather than publishing a partial result. Directory rows must have strictly increasing starts and non-overlapping extents. Parsed runtime ranges can seed function discovery. The metadata is descriptive; it does not evaluate unwind operations against a live register context or execute target handlers.

For AMD64, the loader resolves handler identity only from an exact named export at the handler RVA or a canonical `FF 25 rel32` import thunk (optionally preceded by `ENDBR64`) whose computed slot exactly matches a parsed named import. When that identity is `__C_specific_handler`, its DWORD count and 16-byte scope records are decoded. Count, a 1 MiB payload budget, and table extent are bounded by the image; scope ranges must lie inside the owning runtime-function range, and nonzero filter/finally and jump targets must point to initialized executable bytes. Every record keeps its source spans. A malformed recognized table rejects the whole exception directory atomically.

For a resolved `__CxxFrameHandler3`, the loader decodes the fixed 40-byte
`FuncInfo` header (magic `0x19930522`) and its
bounded unwind map, try-block map, handler arrays, IP-to-state map, and optional
exception-specification type list. State predecessors, try/catch ranges,
relative type and handler pointers, type-descriptor strings, and nonzero cleanup
action RVAs are validated. Source spans are retained for decoded rows and
referenced TypeDescriptors. The 1 MiB per-function C++ metadata budget includes
the exception-specification list and its type names. This remains a partial
description of FuncInfo; the loader does not enforce exception specifications
or execute language handlers. `__CxxFrameHandler4` and unknown
handlers retain explicit unsupported or unresolved status and a source-tracked
opaque preview capped at 256 initialized bytes; the preview does not claim to
represent the full payload. ARM64 language payloads remain uninterpreted.

The desktop PE metadata view exposes AMD64 runtime-function records and
available C/C++ handler rows, plus ARM64 runtime-function and handler rows.
Rows navigate to their source file offset when provenance is available and are
capped at 4,096 entries so large exception tables remain responsive.
