# PE exception-directory function recovery

HexLab parses the exception-directory formats supported for AMD64 and ARM64. ARM64 packed/unpacked records, their bounds, source provenance, and analysis roots are described in [ARM64 PE exception metadata](arm64-pe-unwind.md). The AMD64 path is detailed below.

For PE32+ AMD64 images, the loader reads `IMAGE_DIRECTORY_ENTRY_EXCEPTION` as
a bounded array of 12-byte `RUNTIME_FUNCTION` records. Each record exposes its
begin RVA, exclusive end RVA, `UNWIND_INFO` RVA, and the file spans that backed
the table row in `PeMetadata::exception_functions`.

The loader rejects a table with a partial record, more than the metadata record
budget, out-of-order starts, an empty or out-of-image range, a range outside
initialized executable bytes, or an unaligned, unmapped, or uninitialized
`UNWIND_INFO` reference. Parsing is atomic: a malformed table marks PE metadata
incomplete and adds a diagnostic without publishing partial function rows or
rejecting otherwise usable image bytes.

AMD64 rows must also have strictly increasing starts and non-overlapping
`[begin_rva, end_rva)` extents. This avoids ambiguous function ownership for
addresses covered by multiple entries; chained unwind records remain separate
metadata and do not relax the directory's ordering rule.

Function recovery consumes valid AMD64 record starts as `unwind` roots and
retains the table row index and source file extent with each seed. It converts
RVAs with the image's current mapped base, so rebased PE images recover the same
function boundaries at their new virtual addresses. Existing entry, export,
symbol, and user-defined roots continue to work alongside these rows. Cached
function snapshots preserve the unwind provenance with the root. The validated
`[begin_rva, end_rva)` extent also constrains recovered control flow: fallthrough
or branch paths that leave the unwind range terminate at a chunk boundary unless
the user supplied an explicit function-chunk definition for that entry.

The AMD64 loader additionally decodes version-one unwind operations, chained
records, and validated handler RVAs. It identifies handler names only through
exact exports or canonical import jump thunks. A resolved `__C_specific_handler`
payload is decoded as a bounded count and scope-record table; scope extents must
fit the owning runtime-function range, and nonzero filter/finally and jump
targets must be initialized executable RVAs. Source file spans are retained for
the handler RVA, payload, and each scope row. Resolved `__CxxFrameHandler3`
records also expose the bounded fixed FuncInfo header, unwind map, try-block
map, handler arrays, and IP-to-state map. Try/catch states are checked against
the function's unwind-state count; catch and cleanup targets must identify
initialized executable RVAs. Catch type descriptors retain their decorated
name and source provenance, and IP transitions must be ordered and fall within
the owning runtime-function extent. The parser preserves raw handler adjectives
and frame offsets without executing catch semantics. The optional FH3
exception-specification list now retains its count, image-relative type-array
RVA, per-entry adjectives, decorated TypeDescriptor names, and source spans.
Its rows, descriptors, and names share the per-function 1 MiB metadata budget;
the loader does not enforce the specification during exception dispatch.
The image API `plan_pe_fh3_exception` now maps a live instruction pointer
through the FH3 IP-to-state table, follows validated predecessor states to
return source-backed cleanup action addresses, and lists active try-block
handlers with handler/catch-object addresses and descriptor provenance. It
selects a handler only for an exact decorated-name match or catch-all after all
earlier candidates are provably different. Unknown types, unsupported handler
adjectives, conversions, and rethrow behavior remain ambiguous; it never calls
cleanup or catch code. This is a metadata plan, not a runtime dispatcher.
Because `PeMetadata` is publicly constructible, the FH3 planner repeats the
critical bounds checks at its API boundary. It caps the runtime-function scan
and each FH3 collection (unwind states, IP transitions, try blocks, and
aggregate handlers) at the parser's one-million-record limit. The parser's
1 MiB per-function payload budget can impose a lower effective count. The
planner also caps the combined UTF-8 byte length of handler decorated names
and the caller-supplied exception type at 1 MiB, before comparisons or output
copies. IP transitions must be nondecreasing
and lie in the selected runtime-function extent; duplicate
transitions with one shared state are accepted, while conflicting duplicate
states produce an ambiguous plan. Every IP state,
try/catch range, and unwind predecessor is checked before selection. Cleanup
and handler address additions are checked for overflow. Caller-supplied
overlapping runtime-function extents return an ambiguous plan with a
diagnostic instead of choosing whichever row appears first. Malformed or
oversized tables return an error before candidate traversal/allocation. These
limits apply to the planner independently of parser budgets. When multiple
provable catches remain active and only caller vector order distinguishes
them, dispatch is reported as ambiguous. Dynamic handler
behavior remains uninterpreted. For
`__CxxFrameHandler4`, the loader preserves the one-byte FuncInfo header and
unknown flag bit, decodes the optional BBT value, optional unwind/try map RVAs,
mandatory IP map RVA, and optional catch-frame value. It decodes the compressed
IP-map count and its function-relative delta/state pairs, retaining source spans
for the encoded fields and each entry. When the separated-map header bit is
set, it also decodes the bounded compressed row count and fixed
function-RVA/IP-map-RVA pairs, preserving row provenance and selecting the
entry whose function RVA matches the owning runtime function before decoding
that function's IP map. It structurally decodes the optional unwind map,
try-block map, handler arrays, catch adjectives, type descriptor names,
handler RVAs, and continuation addresses, retaining source spans for records
and encoded fields. Handler continuation addresses follow the header encoding:
`contIsRVA` entries are fixed-width image RVAs, while other entries are
compressed function-relative offsets. Unwind entries retain their backwards link and action RVA;
try blocks retain their state ranges and decoded handlers. The FH4 header also
names its catch-funclet, EHs, and noexcept bits while preserving the full raw
header. `plan_pe_fh4_exception` maps a live instruction pointer through the
function's IP-to-state map, follows validated prior-state links to produce an
ordered cleanup-action plan, and reports active try handlers with exact
decorated-name catch identity, catch-object locations, continuation addresses,
and source spans. Destructor-object actions report their object address;
destructor-pointer actions read one checked 64-bit pointer slot through the
caller memory reader. No destructor or catch code is invoked. The planner can
classify a first source-backed handler candidate when exact decorated-name or
catch-all matching is provable, or report that an FH4 EHs flag requires a
non-C++ exception to continue searching. A C++ exception with no provable
active match in a non-catch-funclet `noexcept` frame is reported as a
`terminate_noexcept` candidate. Unknown exception kind, unsupported catch
adjectives, an earlier unresolved typed catch, and class-conversion/rethrow
semantics remain ambiguous; these metadata decisions never execute dispatch.
Duplicate function rows,
missing owner rows, invalid map RVAs, and non-executable function starts make
the FH4 model malformed. State value `-1` is preserved as the valid encoded
state sentinel; when an unwind map is present, nonnegative try/catch and IP-map
states must refer to one of its entries. Each nonzero unwind-map backward byte
displacement is also resolved against the starts of previously decoded
compressed rows. A target before the map start is retained as the runtime's
null-link sentinel; a target within the map must land exactly on an earlier
row and is exposed as that row's index. Links into the middle of a row or
forward/current-row links mark the FH4 payload malformed.
The integer decoder accepts the 1–4 byte
prefix forms and the five-byte escape form and bounds every read. Map counts are
capped at the shared one-million-record budget, and decoded FH4 table payloads
are capped at 1 MiB per function. Extents must be initialized and remain inside
the image and owning runtime function. A malformed/truncated encoding or
overflowing extent is retained as an explicit malformed FH4 model with a
diagnostic. Unknown header bits remain explicitly unsupported.

The FH4 field and compressed-integer layout follows the public implementation
in [Wine's `handler4.c`](https://github.com/wine-mirror/wine/blob/master/dlls/msvcrt/handler4.c)
and Microsoft's [C++ Team description of FH4](https://devblogs.microsoft.com/cppblog/making-cpp-exception-handling-smaller-x64/).
Because callers may construct `PeMetadata` directly, the FH4 planner independently caps runtime-function, state, handler, continuation, and aggregate decorated-name records before it builds a plan. It rejects overlapping runtime-function ownership, empty function extents, unordered/out-of-function IP transitions, invalid backward unwind links, try-state ranges outside the unwind map, and function-relative continuation addresses outside their owning function. Address additions remain checked. These checks protect the public planning API even when the model did not come from the bounded PE loader.
Other handlers carry an explicit unresolved or unsupported status
plus at most a 256-byte source-tracked opaque preview, which does not claim to
cover the complete payload. ARM64 language payloads remain uninterpreted. The loader does not execute
target handlers.
ARM32 exception-directory layouts remain unsupported and are reported as
incomplete metadata when present.
