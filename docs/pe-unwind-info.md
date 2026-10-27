# AMD64 PE unwind metadata

The PE exception-directory reader decodes x64 runtime-function entries and their version 1 `UNWIND_INFO`. Each runtime range retains source provenance and a normalized prolog-operation list. The decoder covers `PUSH_NONVOL`, both `ALLOC_LARGE` encodings, `ALLOC_SMALL`, `SET_FPREG`, `SAVE_NONVOL` and `_FAR`, `SAVE_XMM128` and `_FAR`, and `PUSH_MACHFRAME`. Handler records and chained runtime-function records are retained, and chained metadata is decoded recursively with cycle and depth checks.

The reader also accepts a bounded subset of Microsoft's preview `UNWIND_INFO_V3`: non-large prologs with no epilog descriptors, using the legacy-register WOD forms for push, stack allocation, frame setup, nonvolatile saves, and XMM128 saves. Prolog IP-offset entries and WOD bytes each retain source provenance in the normalized operation. The ordinary handler and chained-record tails use the same checked parsing path as version 1. V3 large prologs, epilog descriptors, APX-only WODs, and canonical-frame WODs are explicitly unsupported; encountering them rejects the exception directory atomically. This is a preview-format subset, not general APX unwind support. See [Microsoft's x64 Unwind Information V3 preview](https://learn.microsoft.com/en-us/cpp/build/x64-unwind-information-v3?view=msvc-160) for its current encoding.

The exception table is committed as one metadata batch: malformed bounds, flags, operation slots, handler references, language payload records, or chains reject the table rather than publishing a partial result. Directory rows must have strictly increasing starts and non-overlapping extents. The recorded prolog length must fit inside its owning runtime-function extent, including for chained unwind records. Within each version-one `UNWIND_INFO`, a nonzero frame-register field must have exactly one `UWOP_SET_FPREG`; a zero frame-register field must have none. Parsed runtime ranges can seed function discovery. Normalized operations feed the bounded one-frame evaluator described in [PE live-context unwinding](pe-live-unwind.md); target handler code is never executed by that evaluator.

For AMD64, the loader resolves handler identity only from an exact named export at the handler RVA or a canonical `FF 25 rel32` import thunk (optionally preceded by `ENDBR64`) whose computed slot exactly matches a parsed named import. When that identity is `__C_specific_handler`, its DWORD count and 16-byte scope records are decoded. Count, a 1 MiB payload budget, and table extent are bounded by the image; scope ranges must lie inside the owning runtime-function range, and nonzero filter/finally and jump targets must point to initialized executable bytes. Every record keeps its source spans. A malformed recognized table rejects the whole exception directory atomically.

For a resolved `__CxxFrameHandler3`, the loader decodes the fixed 40-byte
`FuncInfo` header (magic `0x19930522`) and its
bounded unwind map, try-block map, handler arrays, IP-to-state map, and optional
exception-specification type list. The FuncInfo EHFlags word retains its source
and names the `/EHs`, dynamic-stack-alignment, and noexcept bits while keeping
unknown bits explicit. State predecessors, try/catch ranges,
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

The FH3/FH4 exception planners expose catch qualifiers from the MSVC adjective
bits (`const`, `volatile`, `unaligned`, and reference binding). For typed catches,
these qualifiers do not prevent an exact decorated TypeDescriptor-name match;
the planner reports the qualifiers alongside the candidate. FH4 `std::...`
catch-all metadata is considered a match only when the caller identifies the
exception as C++; it is a non-match for a known non-C++ exception and unresolved
when the exception kind is unknown. FH3's planner has no exception-kind input,
so the same adjective remains unresolved there. The legacy `bad_alloc`
compatibility bit, COM+ bit, unknown adjective bits, typed uses of `std::...`,
and catch-all qualifiers remain conservative unresolved candidates because
their matching conditions are not available in the planner inputs. These plans
describe candidate selection only and do not invoke handlers or runtime
compatibility logic.
