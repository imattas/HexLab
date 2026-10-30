# Byte signatures

HexLab's analysis library provides bounded, masked byte-signature recognition over executable, file-backed image segments. Results retain the signature name and provenance and report both the original file offset and mapped virtual address. Scanning consumes the project's effective byte source, so project patches are reflected.

## Definition file

The CLI accepts versioned catalogs and the original unversioned definition files. A legacy version 1 catalog starts with the exact header `# HexLab signature catalog v1`. New reusable catalogs use version 2, with a required processor target immediately after the header:

```text
# HexLab signature catalog v2
# target: x86_64/x86_64
```

The target records both architecture and execution mode. A v2 catalog is rejected when scanned against a different image target. Version 1 and unversioned files remain readable as unscoped legacy data; they do not receive this compatibility check. Unknown versions or malformed/unknown targets are rejected.

## Composing catalogs in the analysis API

Library callers can recognize against several independent catalogs in one
operation with `SignatureCatalogSet` and the `scan_executable_signatures` or
`recognize_function_signatures` overloads. The set preserves caller order and
does not merge or rewrite the source catalogs. Each returned `SignatureMatch`
retains its global `definition_index` and its zero-based `catalog_index` within
the set. Duplicate names and patterns remain separate candidates, so the
existing ambiguity behavior is unchanged.

The scanner checks every version-2 catalog against the image architecture and
execution mode before reading bytes, then performs one combined scan. Candidate,
comparison, result, and indexed-byte limits therefore apply to the whole set,
not once per catalog. Sets are limited to 256 catalogs and 4,096 definitions in
total. Version-1 unscoped catalogs can be included; their definitions remain
unscoped and are evaluated against the image selected by the caller. This is an
in-memory API composition only; it does not define a new catalog-set file
format or change the CLI's single `--definitions` input.

`SignatureLimits::minimum_constrained_bits` optionally excludes masked
byte-pattern definitions whose positive pattern has fewer constrained bits
than the requested floor. The default is zero, preserving existing matches;
the maximum supported floor is 2048 bits, matching the 256-byte pattern cap.
Filtered definitions do not contribute scan candidates or consume byte-scan
work when no eligible definitions remain. Pattern validation still runs for
all definitions. This setting affects byte-pattern scans and recovered
function-entry recognition, including catalog sets, but not normalized
instruction-fingerprint recognition. Constrained-bit count describes pattern
specificity only; it is not a confidence score and does not resolve ambiguity.

Each following non-comment line has four pipe-separated fields:

```text
name|provenance|positive-pattern|excluded-pattern[;excluded-pattern...]
```

For example:

```text
Example.Runtime|internal catalog|48 8B ?? ?? 48 85 C0|48 8B 05 10 00 00 00
```

Pattern tokens are two hexadecimal digits, `??` for a full-byte wildcard, or nibble masks such as `A?` and `?F`. A definition needs at least one exact byte. Exclusions are matched at the same start offset as the positive pattern; if any exclusion matches, that candidate is suppressed. Blank lines and lines beginning with `#` are ignored.

The parser caps a definition file at 1 MiB, 4,096 definitions, 128-byte names, 256-byte provenance fields and patterns, and 16 exclusions per definition. For each executable segment, the scanner indexes definitions by the leading byte of each pattern's longest exact-byte run, then verifies only offsets where that run matches. This keeps output deterministic (definition order, then ascending file offset) while avoiding full-pattern checks at every byte. The candidate budget counts anchor hits that proceed to full-pattern verification; the comparison budget includes anchor checks, full patterns, and exclusions; the indexed-byte budget bounds the linear pass over executable bytes. Cancellation is checked throughout. Patterns never cross segment boundaries, and non-executable or non-file-backed segment tails are not scanned.

API callers can set `SignatureLimits::file_range` to scan one bounded file-coordinate window rather than every executable segment. The range must be nonempty and fit inside the effective byte source; scanning is clipped to its intersection with executable, file-backed segments. Positive patterns and exclusions must fit completely inside both the intersection and their segment, so a match cannot borrow bytes outside the requested range. Work budgets count only bytes and candidates inside the selected window. This field is also honored by catalog-set and recovered-function-entry recognition overloads.

## Project CLI

```text
hexlab_cli project signatures sample.hxproj --definitions signatures.txt
```

Optional `--limit`, `--candidate-budget`, and `--comparison-budget` values tune result and work limits within supported hard caps. Each result prints the signature name, provenance, virtual address, and file offset.

## Reusable function catalogs

`create_function_signature` builds a bounded, instruction-aligned prefix from a
recovered function's entry and its explicitly recovered contiguous call or
fallthrough continuation blocks. It verifies the instruction bytes against the
provided effective byte source and decodes them again before using encoding
metadata. Relative call/branch fields and statically addressed memory
displacements become wildcards when the decoder reports a byte-contiguous field
that excludes the opcode. Full-instruction fields and packed/scattered address
fields without byte-span metadata remain exact. Ordinary immediate constants
remain exact so different computations do not match merely because their
constants differ. The default prefix budget is 128 bytes, the hard maximum is
256 bytes, and at least eight exact bytes are required by default. The prefix
stops before an instruction that would exceed the budget, or after the first
non-call control transfer. No bytes are taken from adjacent functions or
unproven continuation blocks.

Missing entry blocks, conflicting blocks, gaps, stale instruction bytes,
changed decode contexts, segmented contexts, unsupported address forms, and
weak prefixes are rejected. Extraction works with nonopaque instructions from
the supported processor decoders. Address-sensitive fields whose encoding span
is unavailable stay exact, so signatures from those functions may only match
the same encoded addresses. The resulting `SignatureDefinition` can be exported with
`serialize_signature_definitions` and read back by the existing parser. The
serializer validates canonical nibble masks and metadata, preventing invalid
or line-injected catalogs.

`create_function_signature_catalog` builds a target-scoped v2 catalog from an
explicit ordered span of recovered `FunctionId` values. It generates stable
`sub_<address-space>_<entry>` names and applies the same effective-byte,
decode-context, instruction-boundary, and minimum-exact-byte checks as the
single-function API. The selection is capped at 4,096 functions; duplicate,
unknown, or stale IDs, duplicate entry addresses, and any function that cannot
produce a valid signature fail the whole operation. The returned catalog can
be written with `serialize_signature_catalog` and passed directly to the
existing single-catalog or ordered catalog-set recognition APIs. The CLI
exposes the all-recovered-functions selection through
`project signature-catalog-create <project> --all-functions --provenance <source>`.
It preserves recovered-function order, writes canonical v2 catalog text to
stdout, and fails without output if recovery is incomplete, the selection is
empty or exceeds 4,096 functions, or any function cannot be signed. `--max-bytes`
defaults to 128 and accepts 1..256; `--min-exact-bytes` defaults to 8 and
accepts 1..`--max-bytes`. Provenance must be 1..256 bytes without `|`, CR, or
LF, and serialized output is capped at 1 MiB. The CLI currently offers only
this all-functions batch selection; `signature-create` remains available for
extracting one function by entry address.

`recognize_function_signatures` groups matches at recovered function entries.
Matches inside functions are excluded. Each entry retains every matching
catalog definition with its name and provenance. Two or more definitions are
reported as ambiguous; no name is automatically assigned and no candidate is
silently selected. Existing scanner work/result budgets and cancellation apply
to the whole executable scan, including matches subsequently filtered out.
An incomplete function snapshot produces an incomplete recognition result.

Every `SignatureMatch` also reports `constrained_bits` (the number of set mask
bits in its positive pattern) and `pattern_bytes` (the full pattern length,
including wildcard bytes). These make raw pattern specificity visible to API
consumers and are retained on function-entry candidates. They are descriptive
counts, not calibrated confidence scores: they do not account for byte
frequency, signature-set prevalence, or compiler/library version. Candidate
ambiguity remains explicit even when one candidate has more constrained bits.

To apply reusable signatures, run the explicit `signature-apply` edit action:

```text
hexlab_cli project signature-apply target.hxproj --definitions library.sig
```

The command considers only recovered function entries. It applies a rename only
when recognition is complete and exactly one catalog definition matches that
entry. Ambiguous entries, duplicate candidate names at multiple entries, names
already used by an existing annotation elsewhere in the same address space,
and entries with an existing user name are skipped. The CLI reports ambiguous
entries, name collisions, and already-named entries separately. Interior byte
matches are never considered. Each applied
name receives a comment line containing the catalog provenance and signature
name; any existing comment text is retained. All selected comments and renames
are validated and committed as one undoable project edit. The action is
explicit; ordinary analysis and `signatures` queries do not rename anything.
Recognition budget exhaustion aborts the action without applying a partial set.

```text
hexlab_cli project signature-create library.hxproj --at va:0x1000 --name Runtime.Helper --provenance "internal library v1" > library.sig
hexlab_cli project signatures target.hxproj --definitions library.sig --function-entries
```

Extraction prints a version 2 reusable catalog scoped to the loaded image's
architecture and mode. Multiple
definitions can be combined in one catalog by appending additional definition
lines after the header. The analysis API exposes `SignatureCatalog`,
`parse_signature_catalog`, and `serialize_signature_catalog` for persistence;
the format preserves each definition's provenance and masks. Optional
`--max-bytes` and `--min-exact-bytes` tune prefix strength; entry recognition
prints candidate counts and an explicit ambiguity flag. Ordinary byte-range
`signatures` scans and `signature-create` are read-only project queries.
`signatures --function-entries` stores the completed recognition evidence in
the project analysis cache. The library can pass one `SignatureCatalog` directly
to either executable scanning or recovered-entry recognition; all entries share
one bounded scan, and output order follows catalog order then ascending file
offset. Catalogs should be selected for the target processor and ABI. Version 2
embeds architecture and execution mode but does not yet embed compiler, ABI, or
library-version metadata.
This is evidence-based byte recognition, not a proof of function identity.
Absolute-address immediates and loader relocations are not normalized by the
byte-pattern format. Compiler-version catalogs, binary `.sig` support, and
automatic library naming remain future work.

## FLAIR text patterns

The desktop **Analysis > Scan FLAIR Catalogs and Browse Results...** workflow
accepts an ordered selection of up to 256 `.pat`, gzip-wrapped `.pat.gz`, and
binary `.sig` catalogs (versions 5-10), then scans the active writable
project's recovered functions in one bounded recognition pass. Aggregate
catalog inputs and inflated bodies are each capped at 64 MiB; the set is
capped at 65,536 patterns. Format dispatch uses IDASGN and gzip magic bytes;
otherwise input is parsed as FLAIR text. Candidates retain their zero-based
catalog index and per-file provenance, including across duplicate catalogs.
Set order and raw catalog contents contribute to the persisted evidence
identity. Its
results dialog reports catalog provenance, parsed pattern count, target, scan
completeness, and work counters, then lists up to 2,000 matching function
entries with candidate names, provenance, and ambiguity status. Select a row
and choose **Go to Selected Function**, or activate the row, to navigate to that
entry. Additional matches remain in the stored evidence and are reported in
the dialog. Recognition evidence is stored in the project's analysis cache;
the scan can be repeated after changing catalogs or project analysis. The
desktop workflow does not rename functions.

The analysis API also imports the human-readable FLAIR `.pat` format with
`parse_flirt_pat`. The caller supplies the architecture, execution mode, and
catalog provenance because `.pat` lines do not carry those fields. Each
pattern's 32-byte masked head, CRC-16/X-25 window, module length, symbol
records, and optional post-CRC tail are retained. The bounded recognizer checks
only recovered function entries in executable, file-backed function chunks.

The text parser accepts one record per line: a 64-character head (32 pairs of
hex digits or `..` wildcard bytes), two-hex-digit CRC length, four-hex-digit
CRC-16, four-hex-digit nonzero module length, one or more `:OFFSET[@] NAME`
public/local records or `^OFFSET NAME` reference records, and an optional
final tail token encoded as hex byte pairs or `..`. Offsets are hexadecimal
byte offsets and must be strictly less than the module length. The CRC window
starts immediately after the 32-byte head; a tail starts immediately after
that window. The tail and CRC window must fit within the declared module
length. Blank lines, leading-whitespace comment lines beginning `#` or `;`,
and a `---` terminator are supported. Inline comments may begin at any
whitespace-delimited token boundary with `#` or `;`; the remainder of that
record line is ignored. Continuation lines remain unsupported. Other malformed
or unsupported syntax is rejected rather than partially imported.

Reference records (`^offset name`) are checked against a direct call at the
recorded function-relative offset. A reference is accepted only when the call
reaches another function with a previously grounded matching signature name.
Unresolved references and reference-only cycles are discarded. Multiple
distinct names remain explicit ambiguity; recognition does not rename
functions. Parsing is limited to 64 MiB, 65,536 pattern records, 128 symbols
per pattern, and 256-byte names and tails. `parse_flirt_sig` also accepts
IDA binary signature catalogs, versions 5 through 10, including
sparse tail bytes, public/local names, reference names, and CRC collision
modules. Its catalog API version stays at 1 while `source_format_version`
retains the original IDASGN version. For `.sig` inputs the catalog also retains
the raw library-name bytes and alternate compiler-type CRC16 from the file header; `.pat`
inputs leave those fields empty/zero because that format does not carry them.
The CLI reports this embedded identity alongside caller-supplied provenance.
The CLI selects `.sig` by its `IDASGN` magic and otherwise uses `.pat`.
Supported catalog targets are x86 16/32/64, 6502, MIPS32/64, ARM32/64,
PowerPC32/64, and RISC-V32/64. Architecture IDs follow the public IDA SDK
processor constants; application-width flags follow the `idasgn_header_t`
definitions. Compressed `.sig` bodies for versions 5 through 10 are inflated
in cancellable 64 KiB chunks: versions 5 and 6 use raw DEFLATE, and versions 7
through 10 use zlib-wrapped DEFLATE. Input and output are independently capped at
64 MiB by default, with a configurable lower output cap through
`FlirtCatalogLimits::max_inflated_bytes`. Cancellation is checked between
chunks, zlib stream checksums are validated when present, and trailing
compressed bytes are rejected. Raw DEFLATE v5/v6 bodies have no wrapper
checksum; successful decoding and full body parsing validate the contents.
Unsupported
architectures/application combinations, versions outside 5–10, and malformed
or over-budget tries are rejected. Gzip-wrapped `.pat.gz` input is supported
through the same `.pat` parser. RFC 1952 optional extra/name/comment/header-
checksum fields are validated; the raw deflate body is inflated in cancellable
64 KiB chunks with independent compressed and inflated caps. The CRC32 and
uncompressed-size trailer are checked, and trailing bytes or concatenated gzip
members are rejected. The CLI detects `.pat.gz` and `.sig` by magic, so gzip
catalogs use the same recognition, provenance, and persisted-evidence path.

Recognition indexes each pattern by its most selective constrained head byte.
It supports partial-bit masks in caller-built `FlirtPatternDefinition` records,
as well as exact bytes and fully wildcarded heads. Imported `.pat` and `.sig`
formats currently provide exact-byte or wildcard-byte head constraints.
Patterns with no constrained head byte use a bounded fallback candidate list;
they still pass through the normal head, CRC, and tail checks and consume the
same candidate/comparison budgets. Candidate processing remains in catalog
order, so masked-anchor support does not change ambiguity ordering.

Recognition validates every symbol record again, including catalogs assembled
directly through the public C++ API. Public, local, and reference offsets must
be nonnegative and fall within the declared module length; unknown symbol kinds
and malformed names are rejected before matching. This prevents an invalid
binary or caller-built catalog from silently dropping out-of-range references
or contributing misleading partial evidence.

Binary `.sig` trie wildcard masks are also required to fit within each node's
declared byte length. Bits beyond the node are rejected instead of being
silently ignored, while canonical masks for all supported versions remain
accepted. This validation applies before trie traversal and prevents malformed
mask encodings from being normalized into apparently valid patterns.

The binary layout was implemented from Hex-Rays' FLIRT technology overview
and checked against the public `fast-flirt` parser documentation/source
(Apache-2.0, format reference only; no code copied) and the open-source
radare2 parser's compressed-stream selection:
https://docs.hex-rays.com/8.4/user-guide/signatures/flirt/ida-f.l.i.r.t.-technology-in-depth
https://cpp.docs.hex-rays.com/idp_8hpp_source.html
https://cpp.docs.hex-rays.com/libfuncs_8hpp_source.html
https://docs.rs/fast-flirt/latest/src/fast_flirt/sig.rs.html
https://github.com/radareorg/radare2/blob/master/libr/anal/flirt.c.

Format coverage is not a full FLIRT corpus compatibility claim: binary `.sig`
versions 5 through 10 and text `.pat`/single-member gzip `.pat.gz` are the
supported import paths, for the processor targets listed above. Compressed
versions 5 and 6 use raw DEFLATE; versions 7 through 10 use zlib-wrapped
DEFLATE. Older and newer binary versions, other compression wrappers, and
concatenated gzip members are rejected. Recognition returns structural pattern matches and
ambiguity; it does not calculate IDA's library similarity ranking or validate
matches against a representative third-party library corpus. Specificity and
ambiguity are evidence only, so false-positive rates remain unmeasured.

The project CLI exposes this recognition path without applying names or
comments:

```text
hexlab_cli project flirt target.hxproj --definitions library.pat --provenance "vendor SDK 1.2"
```

The command supplies the loaded image architecture/mode, prints every grounded
candidate and ambiguity, and reports its pattern/comparison budgets. It reads
the project read-only. To persist source-bound candidates and ambiguity without
renaming functions, use `project flirt-apply` with the same options. Inspect
stored evidence using `project recognition-evidence --kind flirt`. Recognition
evidence format 3 preserves public/local symbol kind, matching-pattern count,
and ordered catalog index, and binds evidence to the analysis key and SHA-256
of the catalog text plus its supplied provenance label. Readers retain support
for evidence formats 1 and 2.

To apply names, add `--rename-unique` to `flirt-apply`. It applies only a single
unambiguous public name when that name does not collide within its address
space, skips functions that already have user names, and appends a provenance
comment. Local names are retained as evidence but are not applied. Incomplete
recognition stores its evidence and applies no names.

The CLI caps catalog input at 64 MiB, patterns at 65,536, functions and results
at 1,000,000 each, candidate and reference work at 67,108,864 each, and byte
comparisons at 268,435,456. Lower per-invocation limits can be selected with
the corresponding budget options.

The desktop Analysis menu scan is available for a saved, writable project with
current recovered functions. It parses and recognizes on a cancellable worker,
stores source-bound evidence without renaming functions or editing comments,
and opens the browsable results dialog when the scanned project is still
active. **Cancel Background Work** requests cancellation; closing the desktop
also requests cancellation and waits for the worker to stop.

## Instruction-normalized function fingerprints

Fingerprint catalogs provide a complementary, typed-function representation.
They hash the recovered function's block/instruction sequence, opcode and flow
kind, typed operands, register effects, relevant architecture context, and
intra-function control-flow edges. Immediate constants and ordinary
base/index displacements remain exact. A relative target or static address
displacement is normalized only when the decoder provides a valid non-opcode
`EncodedField`; packed address fields without such a byte span remain exact.
Before fingerprinting, each instruction is checked against effective project
bytes and decoded again. Opaque instructions, stale facts, unsupported address
contexts, or incomplete function shapes are not guessed.

The v1 catalog records the target architecture/mode, instruction count, SHA-256
of the canonical typed token stream, name, and provenance. Extraction defaults
to at most 512 instructions, 1024 blocks, and 1 MiB of tokens per function;
recognition is bounded to 100,000 functions, 4 million instructions, 256 MiB of
aggregate tokens, and 16,777,216 function-to-definition comparisons by default.
Candidate multiplicity is reported as ambiguity. The
`fingerprints` query never renames functions. It stores completed recognition
evidence in the project analysis cache.

The C++ API and `fingerprints --definitions-list` accept ordered catalogs for
cross-version comparisons. The UTF-8 list has one catalog path per line, with
relative paths resolved from the list file; blank lines and `#` comments are
ignored. CLI inputs are bounded to 256 catalogs and 64 MiB aggregate source
bytes. Recognition supports up to 256 catalogs and 65,536 total
definitions; each catalog must independently target the scanned image. The
function token stream is computed once per recovered function, then compared
against every catalog under the same function, instruction, and token-byte
budgets. `FunctionFingerprintCandidate::catalog_index` identifies its source
catalog. The comparison budget defaults to 16,777,216 checks and has a hard
maximum of 268,435,456. Duplicate candidates remain ambiguous. Persisted
evidence format 3 retains catalog index for every candidate while readers
continue to accept formats 1 and 2. The evidence catalog digest covers the
ordered canonical catalog set, including duplicate entries and order.

Recognition evidence is bound to the full project `AnalysisKey` (image digest,
byte and decision revisions, recipe and engine fingerprints) and a digest of
the canonical catalog text or ordered catalog set. Each function record stores its stable function ID,
entry address, every matching candidate with provenance and specificity or
fingerprint metadata, and the explicit ambiguity state. Byte signatures and
fingerprints use separate cache kinds. Writes are rejected if the current
project key or function ID-to-entry mapping has changed. Evidence records
observations only: it does not create annotations or rename functions. A newer
recognition result replaces the prior cached result for that family and
analysis source.

Retrieve the cached records without supplying or re-running the catalog:

```text
hexlab_cli project recognition-evidence sample.hxproj --kind signatures
hexlab_cli project recognition-evidence sample.hxproj --kind fingerprints
```

The query prints cache status, source image digest and byte/decision revisions,
catalog digest, completeness, every function entry, every candidate, and the
recorded ambiguity. It opens the project read-only and reads the cache on the
project actor's serialized store thread. An absent, stale, incompatible, or
corrupt cache is reported explicitly and returns exit code 3; it is never
recomputed implicitly. A hit whose evidence is incomplete also returns 3.

```text
hexlab_cli project fingerprint-create library.hxproj --at va:0x1000 --name Runtime.Helper --provenance "internal library v1" > library.hxfp
hexlab_cli project fingerprint-create library.hxproj --all-functions --provenance "internal library v1" > library.hxfp
hexlab_cli project fingerprints target.hxproj --definitions-list runtime-versions.txt
```

Use byte signatures when precise encoded prefixes are desired and normalized
fingerprints when the decoded function structure is more stable than its
address-bearing encodings. Fingerprints remain exact hashes, not calibrated
confidence scores or proofs of identity; different block ordering or changed
instructions can produce different hashes, while collisions among catalog
entries remain explicitly ambiguous.

The `signatures` CTest covers linked displacement changes, retained semantic
constants, interior-match rejection, conflicting catalog candidates, whole
instruction truncation, stale facts, insufficient exact bytes, cancellation
and serialization round trips. `project_cli` covers catalog creation from a
reopened project, reusable recognition and explicit ambiguity output.

Validated on Windows/MSVC Debug in a fresh task build:

```powershell
cmake -S . -B .codex-signature-library-build -G "Visual Studio 17 2022" -A x64 -DHEXLAB_BUILD_DESKTOP=OFF -DBUILD_TESTING=ON -DHEXLAB_ENABLE_PINNED_LLVM_ORACLES=OFF
cmake --build .codex-signature-library-build --config Debug --target hexlab_signatures_tests hexlab_cli hexlab_fixture_generator hexlab_project_cli_oracle --parallel 4
ctest --test-dir .codex-signature-library-build -C Debug -R '^(signatures|project_cli)$' --output-on-failure
```

Both CTests passed. The CLI fixture exercises actual call-continuation block
splitting, catalog text output and re-import, and two competing library names.

## Cross-version catalog sets

`signatures` and `signature-apply` accept either one `--definitions` file or a `--definitions-list` file. The list is UTF-8 text with one catalog path per line; blank lines and lines beginning with `#` are ignored, and relative paths resolve from the list file's directory. Up to 256 catalogs and 4,096 definitions are composed in list order, with a 64 MiB aggregate catalog-byte limit. Every catalog retains its own processor target and definition provenance, and all candidates are evaluated under one scan budget. Output includes each match's catalog index when multiple catalogs are present. Duplicate names or patterns from different catalog versions remain separate candidates and therefore preserve ambiguity.

Function-entry scans persist evidence against a digest of the ordered canonical catalog set, including duplicates, so changing catalog order or membership produces distinct evidence identity. `signature-apply` only renames entries with one candidate across the full set; ambiguous results and cross-version name collisions remain unapplied. This supports comparing catalogs collected from different library releases without treating a match as proof of identity or choosing a version automatically.

### Batch fingerprint catalog extraction

`create_function_fingerprint_catalog` builds a portable normalized-fingerprint catalog from an explicit span of recovered `FunctionId` values. It preserves caller selection order, uses deterministic `sub_<address-space>_<entry>` names, and applies the same effective-byte re-decode and completeness checks as single-function extraction. The selection is capped at 4,096 entries; duplicate or stale IDs and any un-fingerprintable selected function fail the operation instead of producing a silently partial catalog. Pass the returned value to `serialize_function_fingerprint_catalog` to write the existing v1 catalog format. The CLI exposes this batch API through `fingerprint-create --all-functions`, selecting the recovered function snapshot in stable order and refusing snapshots larger than 4,096 functions rather than silently truncating them. In this mode, names use the stable address labels; `--name` and `--at` are not accepted. The existing one-function `--at`/`--name` mode remains available.

The Python automation API exposes the same batch operation as
`Project.function_fingerprint_catalog(function_ids, provenance, ...)`. It
returns serialized v1 catalog text, preserves the supplied ID order, and uses
the same all-or-error handling for duplicate, stale, or un-fingerprintable
selections. `expected_revision` can pin the initial project edit revision;
changes to edit or byte revisions during extraction raise
`ProjectChangedDuringQuery`. The Python API accepts a bounded `CancellationToken`
and the same per-function instruction, block, and token-byte limits.
