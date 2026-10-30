# Mach-O implementation validation

Mach-O work is in progress. The full IDA-class objective remains active. Existing
accepted installations are preserved; no Mach-O installed distribution is claimed.

The original C++ shared loader now exposes checked container/header inspection
and selected-slice image mappings. Thin32/64 and FAT32/FAT64, both byte orders,
retain full CPU fields and absolute outer-container coordinates. Slice-crossing
reads, overlapping descriptors, invalid command envelopes and conflicting linked
backing fail. MH_OBJECT sections have independent one-based domains at offset0;
64-bit Mach headers and FAT64 architecture descriptors must have zero reserved
fields. Nonzero reserved words are rejected as malformed instead of being
accepted as unexplained metadata.
raw nonzero/equal section origins remain in metadata. Linked segments govern
backing, with explicit partial diagnostics for disagreeing section declarations.
SG_HIGHVM, no-access reservations and zero-fill section types are covered.
Unsupported CPU/class/order combinations preserve metadata with unknown decode
mode. Original nlist symbols, library/path commands, entry declarations, function
starts and dynamic symbol group/indirect-table metadata are now implemented.
`LC_UUID` commands are accepted only with the specified 24-byte command size;
the 16 UUID bytes are retained with command index and absolute outer-file record
offset plus the exact UUID payload offset, and printed in canonical hexadecimal
grouping. This reports the embedded
identifier only: it does not authenticate a file, establish equivalence between
universal slices, or validate external symbol-server associations. CLI output is
bounded to 16 UUID rows.
Executable definitions seed recovery as heuristics rather than declared function
types. LC_MAIN follows dyld: mapped Mach-header VA plus entryoff; unsupported or
conflicting entry declarations stay explicit. Object relocations, dyld reference
semantics and frontend integration remain in the plan.

The selected-slice loader now assigns decoder modes to bounded ARM32, MIPS32
and PowerPC32 slices in either byte order, and to PowerPC64/MIPS64 slices with
their supported mode. Universal selection retains the existing little-endian
x86/x86-64/ARM64 preference and falls back to supported 32-bit or big-endian
slices before descriptor order. Metadata identifies class and byte order
(`Mach-O32`/`Mach-O64` for little-endian and `Mach-O32-BE`/`Mach-O64-BE` for
big-endian); every outer file offset remains absolute to the universal container while section-relative
addresses retain the selected slice's address spaces. Generic header, command,
segment/section, nlist, and relocation records use the selected slice's byte
order and class widths. Architecture-specific big-endian relocation formulas,
thread-state decoding, and unsupported command payloads stay explicitly
incomplete and are not applied as guessed semantics.

Section alignment is checked against both the declared VM address and, for
nonempty file-backed sections, the raw file offset. Alignment exponents outside
the address width or values that violate the declared power-of-two alignment
are rejected before the section is mapped. Zero-fill sections have no file
payload and therefore receive only the address-alignment check.

Observed evidence under out/: macho-task1-red.log -> macho-task1-green.log;
Task1 Debug4/4 and Release4/4 with572 header checks. Task2 missing image API RED
macho-task2-red.log -> macho-task2-green.log. Section disagreement regression
RED macho-task2-disagreement-red.log -> GREEN
macho-task2-disagreement-green.log. Headless Debug full73/73 in
macho-task2-full-debug.log; headless Release73/73 in
macho-task2-full-release.log and desktopDebug86/86 in
macho-task2-full-desktop.log. All consumers rebuilt for the public metadata
layout extension. The image target has82 checks, including the additional
section/segment disagreement regression.

Fresh clang i386/x86_64/arm64 original C objects and an ld64.lld-linked x64 image
were independently inspected by LLVM. An original standalone host probe matched
header/section/segment scalar projections for all4. Files, exact subprocess
observations and hashes are under out/macho-task2-independent/. No input was
executed. These are focused mapping checks; formal differential oracle, new
installed SDK/native acceptance and fresh final stage review remain pending.

Design: docs/superpowers/specs/2026-10-20-macho-design.md.
Plan: docs/superpowers/plans/2026-10-20-macho.md.

Task3 adds full-width32/64 both-order nlist originals, STAB/common/absolute/indirect/
undefined/TLV states, nonUTF8 names, weak/private/alternate descriptor bits and
source namespaces. Actual saved ProjectSessions prove domain-local naming, user
overrides, metadata string patches/undo and source-missing readonly cache/history.
Minimum explicit Mach-O recipe/dispatch support moved forward for that proof;
automatic detection, OpenRequest/actors and CLI/native controls remain Tasks5/6.

Observed Task3 gates: headless Debug77/77 and Release77/77; desktopDebug90/90
without concurrent compilation. Evidence: out/macho-task3-full-debug.log,
macho-task3-full-release.log and macho-task3-full-desktop-idle.log. An earlier
desktop run during Release compilation had one45s desktop_elf timeout; unchanged
isolated execution passed2.26s and the whole unchanged idle suite passed24.82s.
The timeout/assertions were not relaxed. Symbol/command/project targets have
86/40/10 checks respectively. Existing PE/ELF/segmented regressions stay green.

A rebuilt original host probe matches LLVM raw symbol names/indexes/types/section/
descriptors/values for4 original compiler/linked fixtures; task3-comparison.json
is under out/macho-task2-independent. No input executed. Formal oracle remains
Task7. A genuine format5/enginev13 Mach-O derived cache, original input, producer,
435-file source snapshot and matching8-DLL Debug runtime are preserved under
out/macho-cache-v5-capture for future compatibility testing. No version bytes or
checksums were rewritten. The engine fingerprint advanced; current cache wire
and user schema remain unchanged.

Task4 is in progress. The original relocation reader preserves normal32/64,
both-order bitfields, scattered/pair records, source namespaces, absolute outer
record offsets and original field bits. Linked retained records are not applied
again. Focused regressions cover debug/file-only aliases and signed classic x64
runtime offsets relative to the first writable segment.

The separate public MachORelocationResolver has bounded indexed lookups,
cancellation and typed Mach-O unresolved states. Its focused48 checks cover
external/local x86/x64 object calls, RIP-relative memory with trailing immediates,
raw data associations and same-domain subtractor constants. Field-width and
unknown CPU/class contexts cannot inherit an unsupported address formula. These constants are
distinct from addresses. This was the initial resolver checkpoint; shared
integration and schema replacement are described below. Dyld parsing remains
pending.

The rebuilt host probe matches31 raw relocation projections from6 independent
LLVM-observed inputs, including newly authored i386/x64 assembly with scattered
pairs/subtractors and PC-relative memory. Commands, input/output hashes and scope
are in out/macho-task2-independent/task4-relocation-comparison.json. Input code
was never executed. This is preliminary parser evidence, not the Task7 oracle.

Final raw-parser/resolver checkpoint gates on the current source: headless
Debug79/79, Release79/79, desktopDebug92/92. Logs are
out/macho-task4-final-debug.log, out/macho-task4-full-release.log and
out/macho-task4-full-desktop-idle.log. Desktop tests ran after the other build/test
processes finished. Raw relocation70/resolver48 checks pass. The6-input LLVM
comparison was rerun after the parser precision fixes with unchanged hashes and
all31 scalar records matching. No Mach-O stage completion or installation is
claimed by that checkpoint. The following continuation adds shared flow and
owned reference provenance; dyld and frontend work remain.

The shared RelocationResolver now dispatches recovery, coarse reachability,
manual listing and reference derivation to the original format-specific rules.
Mach-O unresolved stops/reasons are distinct from ELF. References own selected
slice context, complete relocation/table records and available nlist namespace/
symbol copies. incoming_macho_symbol indexes both defined and undefined symbols;
project Follow accepts these current-source references. Indirect calls associate
the pointer slot while leaving the stored callee unknown. Same-domain subtractor
results remain scalar constants; they cannot become numeric pointer targets.

The engine fingerprint is v15 with macho-relocation-flow-v1 and
macho-reference-provenance-v1. Derived/reference cache schema6 and reference
payload5 reject incompatible old records. Ordinary reference record tag2, stable
IDs and body bytes are preserved. The genuine prior Mach-O v13 payload is tested
under its actual original database key and under a current-key forgery without
rewriting its payload, version or checksum. Read-only source-missing recomputation
preserves user annotations, UUID, revisions, history and original cache bytes.
Historical ELF caches retain equivalent rejection/history checks.

Focused checks: flow118, owned references30, old Mach-O cache13. Actual saved
projects prove relocation patch/stale Follow rejection, refresh to unresolved,
undo/recompute, source-missing readonly cache hit and indexed symbol references.
Valid checksums/recomputed IDs cannot substitute another symbol's owned name in
the full source-bound cache. Scalar changes, paired-origin reordering and symbol
namespace substitutions are rejected. Empty n_strx0/string-table references,
trailing immediate/BSS associations and indirect memory references roundtrip.
Evidence: out/macho-task4-reference-final-focused.log and
out/macho-task4-cache-version-green.log. Full rebuilt consumer gates for this
continuation are now complete: headlessDebug82/82 (65.82s), Release82/82 (51.35s)
and desktopDebug95/95 (96.96s). All source consumers rebuilt after the public
Reference/ReferenceIndex layout change. Desktop tests ran alone after other
build/test processes finished. Evidence: out/macho-task4-flow-full-debug.log,
out/macho-task4-flow-full-release.log and
out/macho-task4-flow-full-desktop-idle.log. The protected accepted ElfDebug
installation's698 hashes remain unchanged. These are core integration/regression
gates; dyld, native Mach-O frontend and formal oracle/installed SDK gates remain.

A later Task4 metadata checkpoint adds original classic dyld rebase/bind/weak/
lazy stream readers and iterative export-trie parsing. It preserves stream,
opcode, repeat, segment, library-ordinal, symbol, addend and original field-bit
facts in selected-slice outer coordinates. Symbol strings, ULEB/SLEB, repeat
counts, field extents and total work/allocation are bounded and cancellable.
Lazy entries reset independent state; weak streams do not invent an explicit
dependency ordinal. Byte sampling uses file-order requests, including alias and
split-field handling. Shared command header/__TEXT anchors and library counts
are precomputed rather than rescanned per command.

Export nodes preserve names, flags, terminal source offsets, ordinary values,
reexports and separate stub/resolver declarations. Absolute/TLS values do not
become invented image pointers, and no resolver is executed. Active-path cycle
checks permit shared suffix nodes; a2048-node path and deep cycle are tested.
Both dyld_info and LC_DYLD_EXPORTS_TRIE use the same bounded reader. Threaded
binds, chained payloads and unknown semantic flags remain explicit partial
declarations. Shared runtime-binding suppression/owned dyld provenance, export
root/name integration and data/encryption exclusion remain pending; the earlier
relocation-aware shared pipeline does not yet consume these new dyld facts.

The focused dyld target passes73 checks. A newly authored compiler/ld64.lld
classic dylib matches observed LLVM projections for6 fixups and4 exports,
including weak/lazy/flat-namespace state. Exact source/input/output hashes,
commands and tool versions are recorded in
out/macho-task2-independent/task4-dyld-comparison.json; no input code executed.
The prior31 raw relocation projection also remains exact after the new parser.
These are preliminary independent proofs, with the formal oracle still Task7.

Before extending MachOMetadata, an actual v15/schema6 payload was captured from
ProjectSession/ProjectStore:3215 bytes SHA256
5289ffa0d3448156f52e12059040ef82f3c97c311d4374582e14e86a7e9c1727,
with its original input, producer, DB,451-file source snapshot and matching8-DLL
runtime under out/macho-cache-v6-capture. Original fixture bytes and provenance
are promoted under tests/fixtures/derived_v6_macho_v15*. No header, key or
checksum rewriting. The v13/schema5 capture is also preserved. Public metadata
layout changed in this checkpoint; all consumers have now rebuilt. Final gates:
headlessDebug83/83 (76.62s), Release83/83 (53.55s), desktopDebug96/96 (85.31s).
The desktop suite ran alone after the other build/test processes finished. Logs:
out/macho-task4-dyld-full-debug.log, out/macho-task4-dyld-full-release.log and
out/macho-task4-dyld-full-desktop-idle.log. No timeout or assertion was weakened.
The accepted ElfDebug698 file hashes and complete genuine v15/schema6 capture
were rechecked unchanged. Chained/threaded parsing, dyld-aware shared analysis,
code/data/encryption gates and remaining project/frontend/install work are still
pending; this checkpoint does not complete Task4 or the full objective.

The next metadata checkpoint adds original LC_DYLD_CHAINED_FIXUPS decoding:
versioned fixed header, all3 import forms, bounded source string pool, original
segment/page/multi-start arrays and pointer-chain traversal. Supported word
layouts are generic32, generic64, generic64_OFFSET and ARM64e1/9/12. Imports keep
raw record/addend bits and exact namespace;8-bit ordinals128..240 remain positive
while only the top15 encodings represent negative special scopes. Pointer words
retain raw bits, next/stride, bind ordinal, target payload/high8 and authentication
diversity/address-diversity/key. PAC and runtime pointer targets are not computed.
Co-opted32-bit values remain scalar patterns. Overlapping words stay inspectable
with partial semantics; converging/duplicate chains and out-of-page/segment hops
are rejected. A file-order priority queue bounds dependency-read insertion work.

Focused coverage115 checks includes every fixed-header truncation, import/name/
page/segment/next bounds, pointer widths, multi-start indexes into the full
original array, special ordinals, authenticated words, scalar restoration,
successful short reads and cancellation during actual pointer I/O, zero-fill,
unknown/compressed layouts and selected universal slices. Evidence:
out/macho-task4-chained-final-focused.log and actual overlap RED/GREEN logs.

A fresh LLVM-observed dylib and executable each match2 imports,2 segment-start
records and3 raw pointer/address/bind/rebase rows. The executable includes an
observed PAGEZERO and checks preservation of raw segment ordinals. Exact tool
versions/commands/source/input/output hashes are recorded in
out/macho-task2-independent/task4-chained-comparison.json. Authentication remains
literal-format evidence, not a claimed compiler-authentication oracle. Inputs
were never executed. The classic6-fixup/4-export comparison also remains exact.
Public MachOMetadata grew again; all source consumers rebuilt. Full checkpoint
gates passed: headlessDebug84/84 (98.36s), Release84/84 (55.84s), desktopDebug97/97
(106.50s). The desktop suite ran alone after all compilers and other test jobs
finished. Logs: out/macho-task4-chained-full-debug.log,
out/macho-task4-chained-full-release.log and
out/macho-task4-chained-full-desktop-idle.log. No timeout or assertion was weakened.
The accepted ElfDebug698 inventory records and all465 genuine v15 capture
file/runtime/source/producer records were rechecked unchanged after the gates.
Enginev15/cache6/refpayload5 are unchanged because shared dyld
binding/reference/root analysis is still pending. Old threaded streams, code/
encryption guards and Tasks5-7 remain open; no Mach-O stage completion is claimed.

The next analysis checkpoint adds the original public MachODyldResolver. It
borrows immutable image/metadata, indexes exact canonical slot intervals and
keeps classic opcode rows separate from chained pointer/import namespaces.
Supported pointer rebases produce preferred-space addresses; chained offsets
require a unique, contiguous mapped Mach header. High8 bits remain significant.
Runtime bindings own raw names, optional dependency ordinals and checked combined
addends; they never become numeric host-library targets. Authentication,
nonpointer scalars, unsupported text fixups, unavailable fields, arithmetic
failure and competing origins have distinct outcomes. Index allocation is
bounded64MiB; lookup work and4096 matches are bounded and cancellable.

Focused64 checks pass, including both classic widths/orders, all six supported
chained layouts, weak coalescing without a guessed ordinal, compressed import
names, positive/negative addend overflow, source namespace/backing errors,
header aliases, partial/overlapping words, high8 and no repeated source I/O.
Actual missing-API RED: out/macho-task4-dyld-resolution-red.log. Focused GREEN:
out/macho-task4-dyld-resolution-final.log. Full build/regression gates passed:
headlessDebug85/85 (92.82s), Release85/85 (79.68s), desktopDebug98/98 (117.96s).
The desktop suite ran alone. Logs: out/macho-task4-dyld-resolution-full-debug.log,
out/macho-task4-dyld-resolution-full-release.log and
out/macho-task4-dyld-resolution-full-desktop-idle.log. No timeout or assertion was
weakened. The accepted ElfDebug inventory and both genuine Mach-O cache archives
were rechecked unchanged after the gates.
This API is not yet consumed by shared recovery/references/Follow and changes no
engine fingerprint or cache wire. Actual v15/schema6 compatibility/history tests
remain mandatory before the next semantic integration changes engine or wire.

Raw dyld reference integration now consumes the public resolver in shared
reference derivation. New distinct dyld-fixup/macho-dyld kinds own original
classic emit operation and state, or chained header/pointer/import records and
fixed start context, plus selected-slice/stream identity. Page arrays are not
repeated per pointer. Canonical proof serialization preserves ordinary reference
record tag2/body/IDs. Original pointer/import bits constrain copied semantic
fields; width32 words cannot acquire high bits. A forged import name with valid
new reference IDs and a recomputed full-cache checksum is rejected by rooted
source validation. Runtime bindings remain unresolved with raw optional library
ordinal/name/addend, never host-library addresses.

Actual captured v15/schema6 migration tests were added before changing engine
or wire. They initially failed four assertions under enginev15, then passed for
original keys and unchanged old payloads rekeyed under the new engine. Read-only
recomputation preserves embedded input, UUID, user annotation/revisions/history
and every original DB cache byte/version/key. Both v13 and v15 producer archives
remain immutable. Current engine is v16 with macho-dyld-data-provenance-v1;
derived/reference cache version7, reference payload6. Historical ordinary records
are not rewritten. Shared decoded instruction operand/recovery/Follow dyld
integration remains required; this checkpoint supplies owned raw slot references.

Focused44 raw-dyld checks and26 genuine historical-cache checks pass. Coverage
includes all supported chained layouts, classic32/64 both byte orders, scalar/
authenticated/overlapping/compressed-name partial facts, canonical roundtrips,
actual standalone raw-word/ordinal/width RED/GREEN, full derived-cache forgery,
project pointer patch->stale barrier->refresh->undo and source-missing read-only
cache hit with preserved annotations/history. Evidence: out/macho-task4-v15-cache-red.log,
out/macho-task4-dyld-owned-word-red.log, out/macho-task4-dyld-narrow-word-red.log
and out/macho-task4-dyld-compact-proof-green.log. An independent same-MSVC Release
size probe found that an inline proof grew common references from384 to640 bytes.
Immutable proof ownership reduced this to400 bytes, with publication freezing its
own value against caller-retained mutable aliases. Actual pre-change classic and
chained wire hashes remain exact; ordinary records/IDs remain unchanged.

All source consumers rebuilt for the final public layout. Full gates passed:
headlessDebug86/86 (101.04s), Release86/86 (49.50s), desktopDebug99/99 (135.73s).
The desktop suite ran alone after all other build/test processes ended. Logs:
out/macho-task4-dyld-compact-full-debug.log,
out/macho-task4-dyld-compact-full-release.log and
out/macho-task4-dyld-compact-full-desktop-idle.log. No timeout or assertion weakened.

A new genuine current-engine capture is sealed under out/macho-cache-v7-capture.
The producer ran once through actual ProjectSession/ProjectStore with the final
Debug ABI, preserved captured_dyld_owner annotation and natural rooted analysis:
3 functions,385 references including2 owned dyld fixups. Original derived payload
100131 bytes SHA256976f33b520adc9f2c1b7dbd442c1ea09ac7c6883a2fe4c2d67887bc174129ede;
reference payload29262 bytes SHAb39a67a192bce7fd5670ad8b94a2c35eaa05a8f7a22c91f41a97e9b36610a067;
input4096 bytes SHAc521e2bcbc613ee5670134f2fc67361aa004c724ff2bffa5134edaaf9c1d4261.
Engine SHA69464eb07957a5d66ee191420028d6276e11209b2973213a43274d28dede1a7f.
Matching8 DLLs, producer executable,469-file source snapshot,8 import libraries
and8 generated headers are retained with all501 hashes verified. Five original
payload/input/reference/producer/provenance fixtures were promoted byte-identical
to tests/fixtures. No producer rerun, historical header/key/checksum rewriting or
analyzed-input execution. The accepted ElfDebug698 hashes and prior v13/v15
archives'448/465 recorded hashes were reverified unchanged. Decoded dyld operand/
recovery/Follow, export roots/indexed names, data/encryption guards and Tasks5-7
remain open. Neither Task4, the Mach-O stage nor the full objective is complete.

Decoded dyld flow continuation (verified source checkpoint): the shared
image-aware resolver now separates encoded operand fields, pointer storage reads
and opcode-byte overlaps. Indirect control may use a uniquely resolved preferred
pointer only when its target is initialized executable storage outside another
known fixup. Runtime bindings remain unresolved. Memory references keep their
storage address, while control references own both the storage association and
the original pointer provenance. A relative CALL field never becomes an absolute
pointer equation. Fixups covering opcode bytes stop automatic traversal; fixups
inside valid immediate fields permit complete decoding. Pure decoder bytes remain
unchanged. Recovery, coarse analysis, listing and project Follow share this path.

Focused tests pass:40 decoded-flow checks, including actual project pointer
patch/stale Follow/refresh/undo, source-missing read-only cache hit with UUID/user
history preserved, immediate/relative/opcode cases, storage-root exclusion,
cancellation, canonical reference roundtrips and source-bound query-span forgery.
The final focused three-test gate also includes owned raw dyld references and
genuine prior-cache migration (out/macho-task4-dyld-flow-final-focus.log).
Before the semantic change, actual v16 cache migration produced its expected
four failures under the old engine (out/macho-task4-v16-cache-red.log).
The genuine archived v16 reference payload is pinned by its original hash and
rejected by the incompatible current reader. No historical payload was rewritten.

Current engine is v17 with macho-dyld-flow-v1, derived/reference cache version8,
reference payload7 and dyld provenance version2. Ordinary record tag2 is retained;
dyld records now include their use and bounded query spans. The shared immutable
proof keeps additional query state outside common inline Reference storage.
All source consumers rebuilt and full tests passed: headlessDebug87/87
(133.16s), Release87/87 (104.05s) and desktopDebug100/100 (163.99s). Evidence:
out/macho-task4-dyld-flow-full-debug.log,
out/macho-task4-dyld-flow-full-release.log and
out/macho-task4-dyld-flow-full-desktop-idle.log. The desktop suite ran alone after
both build jobs and all other compiler/test processes ended. No assertion or
timeout was weakened. The final process audit found no remaining build/test jobs.
Compiler deprecation/signedness/shadow warnings remain; this is not a warning-free
build claim. Preservation audit verified accepted ElfDebug698 and genuine
v13/v15/v16 captures448/465/501 recorded files with zero mismatches
(out/macho-task4-dyld-flow-preservation-audit.json).

Export roots/indexed names, LC_DATA_IN_CODE/encryption guards and Tasks5-7 remain
open. This checkpoint completes decoded dyld integration, not Task4 or the full
objective. Capture genuine v17/cache8 producer payloads and matching source/runtime
before the next accepted engine/cache advance; never rewrite historical payloads.

Export integration continuation (verified source checkpoint):
complete regular, weak and stub/resolver definitions now seed rooted and coarse
analysis through existing initialized/execute/fixup permissions. Reexports, TLS,
absolute scalars and partial unknown declarations do not invent code roots.
Non-executable mapped exports retain their name. Export names use a separate
worker presentation namespace after nlist, with the aggregate record budget and
the same collision behavior in indexed/fallback paths. User annotations take
precedence. Actual project trie edits move roots/names, retained snapshots stay
immutable, undo restores original source, and source-missing read-only cache
reopen preserves user annotations, UUID/revisions/history. The new 37-check
export corpus and 52-check genuine migration corpus pass the focused gate
(out/macho-task4-export-flow-final-focus.log). Full rebuild/regression gates also
passed: headlessDebug88/88 (127.87s), Release88/88 (73.47s), desktopDebug101/101
(121.60s). Logs: out/macho-task4-export-full-debug.log,
out/macho-task4-export-full-release.log and
out/macho-task4-export-full-desktop-idle.log. Desktop ran alone after both builds
and other compiler/test processes ended. The final process audit found0 remaining
build/test processes. No timeout/assertion weakened. Compiler warnings remain;
this is not a warning-free build claim.

Before the engine change, an actual v17/schema8 producer ran once in a new
out/macho-cache-v8-capture prefix. Its original input has a rebased and a bound
indirect CALL:2 functions,6 references (2 raw and4 decoded dyld uses), with actual
Follow available only for the rebase. Derived payload6019 bytes SHA256
aa60c2d083e79069bc5b382b55bb5d2514050be7b1c8a3258693249899b4ea33;
reference payload2593 bytes SHA256
5c93e8a9aca9507def513cb4541419dcc1873dff0e4627857d3bc406e7f153fc.
Matching source475 files,8 DLLs,16 SDK files, producer executable and6 captured
files total506 hash records; independent audit found0 mismatches. Five promoted
fixtures match their originals byte-for-byte. No archived producer was rerun.
The final preservation audit also verified all448/465/501 records in the three
earlier captures and698 files in accepted ElfDebug, with0 mismatches
(out/macho-task4-export-preservation-audit.json).
Actual v17 migration first produced52 checks/4 expected failures under engine17;
the new export behavior first produced26 checks/10 failures. Original keys,
payloads and checksums were not rewritten to simulate either historical engine.

Current engine18 adds macho-export-roots-v1. Wire schemas remain derived/reference
cache8 and reference payload7: export roots use existing seed records. A genuine
v17 payload rekeyed under engine18 keeps a different embedded source identity and
is rejected as corrupt, while older wire versions are incompatible. Neither is
adopted. LC_DATA_IN_CODE/encryption guards and Tasks5-7 remain required; this is
not Task4 or full-objective completion.
Before another accepted engine advance, capture real current-engine18 bytes and
matching source/runtime in a fresh prefix. Engine18 retains wire8, so a new capture
must not overwrite the existing engine17/schema8 archive or assume monotonically
increasing wire versions in historical-fixture tests.

Data/encryption guard continuation (verified source checkpoint):
original DATA_IN_CODE, ENCRYPTION_INFO/64 and CODE_SIGNATURE declarations now
retain source offsets, raw widths/kinds/cryptid/padding and selected-slice bounds.
Image code exclusions and encrypted ranges are separate canonical unions;
encrypted ranges always exclude decoding. All initialized aliases and high VM
backing placement participate. Original segment permissions and bytes remain
unchanged. Recovery seeds, per-byte decode windows, cached-fact reuse, coarse
analysis, image/manual listing and project Follow use the policy. Data/encrypted
targets do not become decoded callee functions or Follow destinations; a valid
plain-source branch may still retain its declared numeric destination as an
address reference. Empty policies preserve historical mapping hashes; nonempty
policies bind canonical ranges to source identity.

Object DATA_IN_CODE offsets use object VM coordinates, unlike linked file
offsets. An actual Clang23.1.3 x86_64 object and observed llvm-readobj output prove
sectionVA0/file320 and data offset5/length4/kind1: physical325/domain1 offset5.
The original400-byte object SHA256 is
d2e82a2bd995313d1eaf25da0e1c6a9f7972f584e007c77d0196cf15a386f1ff.
The source, object, LLVM readout, tool hashes/identities and commands are retained
under tests/fixtures/macho_guard_x64* and out/macho-guards-independent. Ambiguous
or multi-section object relationships remain explicitly partial with no invented
unique backing; every mapped candidate/intersection is excluded. Ciphertext
chained next/ordinal bits cannot drive traversal or import association. Classic/
chained dyld and both public relocation APIs suppress encrypted value equations
while retaining raw source evidence. Signatures are declared, never authenticated;
cryptid0 leaves bytes unencrypted. Unknown data kinds remain partial and excluded.

Focused104 guard checks and65 genuine old-cache migration checks pass
(out/macho-task4-guards-final-green.log). Actual RED evidence includes initial
56checks/35failures, compiler-object/cipher67/3, source-binding/object98/2 and
metadata-only relocation104/1. Coverage includes32/64 both orders, FAT32/64
native/swapped coordinates, command minima/table/target bounds, cancellation and
limits, SG_HIGHVM/aliases, domain/overflow/width checks, checksum-valid cache
forgery with correct mapping hash, manual/reference/source-fact barriers and real
project cryptid patch/refresh/undo/source-missing read-only cache with annotations,
UUID/revisions/history preserved. Full source consumers rebuilt and passed:
headlessDebug89/89 (140.41s), Release89/89 (70.63s), desktopDebug102/102 (102.43s).
Logs: out/macho-task4-guards-full-debug.log,
out/macho-task4-guards-full-release.log and
out/macho-task4-guards-full-desktop-idle.log. Desktop ran alone after both build
jobs and all other compiler/test processes ended. Final process audit0; no
assertion/timeout weakened. Existing compiler warnings remain, so this is not
a warning-free build claim.

Before engine19, a genuine engine18/schema8 producer ran once in the new
out/macho-cache-v8-v18-capture prefix: export-only root/name, two dyld calls,
2functions/6references. Derived6175 bytes SHA256
6e3ee89d40e58dc289074b176737d8770540d49e6e3892980962cf0d353bea4d;
references2593 bytes SHAc99abb79f64665ba3748ebc1fbe8b44ff1260bbcf8d83ed40171b212141ad2fd;
input4096 bytes SHA563f4e55990c5e96acf01b2aef41c81db185548c5077fa8d3355a47b3fd7e85a.
Matching source481/runtime8/SDK16/producerEXE1/files6 total512 hash records,
verified0 mismatches. Five fixtures were promoted; no archived producer rerun or
historical key/header/checksum mutation. Actual prior-engine RED65checks/4failures
preceded the new engine. Historical versions are explicit5/6/7/8/8, with unchanged
payloads tested under old keys and current keys in read-only embedded projects.
Current engine19 adds macho-code-policy-v1; derived/reference cache8, reference
payload7, dyld proof2 and ordinary record2 remain unchanged. Public ImageLayout/
MachOMetadata ABI changed, so all consumers must rebuild; archived runtimes and
SDK consumers remain paired and immutable. Preservation audit verifies accepted
ElfDebug698 and five captures448/465/501/506/512 with0 mismatches
(out/macho-task4-guards-preservation-audit.json). Neither the stage nor the full
objective is complete; durable selection/workers/frontends/distribution still
require Tasks5-7 and final whole-stage review.

Durable project/opening continuation (verified Task5 checkpoint):
opening requests and saved recipes now have separate dispatch. New
load_durable_image binds thin flag0 versus universal flag1/index before ranking;
project refresh/reopen uses it. Public load_image still resolves opening intent.
Database import resolves actual format/slice before writing input identity and
recipe. Eight thin/FAT/class/order signatures append macho_candidate without
moving old ordinals; short prefix reads fail cleanly and malformed candidates do
not become raw images. OpenRequest appends optional MachOOptions; automatic and
explicit worker opening share the resolver and reject conflicting options.

Actual project RED12checks/7failures preceded the fix
(out/macho-task5-project-red.log). Final focused59 project,13 worker and5 recipe
checks pass (out/macho-task5-final-focus.log). Coverage includes both container
kind changes through patch/undo/redo, exact recipe/UUID/annotation preservation,
default and explicit nondefault imports, selected CPU/ranking changes and removed
descriptors, stale instruction suppression, cancellation before reads, all magic
variants and both-order inspection, metadata-only actor opening, held canceled
imports and held obsolete analysis completion. Ordinary selected/unselected code
patches avoid metadata reparsing. Exports preserve the exact whole container and
both patches while original bytes remain unchanged. Save As gets a new UUID;
source-missing read-only reopen restores selected slice, cache, annotations,
revisions and history and rejects mutation.

Engine19/cache8/reference payload7 remain unchanged: valid analysis derivation
semantics and serialization are unchanged. Public opening APIs/layouts changed,
so all source consumers rebuilt. Full gates passed: Debug91/91 (86.01s),
Release91/91 (73.09s), desktopDebug104/104 (111.45s), with desktop alone after
both builds and all other compiler/test processes ended. Final process audit0;
no assertions/timeouts weakened. Logs: out/macho-task5-full-debug.log,
out/macho-task5-full-release.log and out/macho-task5-full-desktop-idle.log.
Preservation audit verifies all3130 recorded files across accepted ElfDebug698
and historical captures448/465/501/506/512 with0 mismatches
(out/macho-task5-preservation-audit.json). Existing compiler warnings remain;
this is not a warning-free build claim. Dedicated CLI options and native Mach-O metadata/slice controls,
formal fresh oracle, installed SDK/distribution/offline/BTOFF and one final
whole-stage review remain Tasks6-7. Historical scalar comparison artifacts keep
their preliminary scopes; they do not establish runtime/authentication support.

Task6 CLI checkpoint: both standalone and project-create parsers now accept
`--format macho` and zero-based `--slice` with checked bounds and conflicting
option rejection. Saved project commands cannot override the durable slice.
The shared CLI formatter exposes original Mach-O headers, container descriptors,
commands, segments, sections, symbols, library paths, relocations, classic dyld,
exports, chained records, data-in-code, encryption and unauthenticated signatures.
Disassembly annotates source-bound relocated control targets without changing
instruction bytes or the pure decoder. Unsupported targets remain unresolved.

The new original fixture generator and CMake CLI suite first failed 36/49
behavior checks before implementation (`out/macho-task6-cli-red.log`). The
expanded suite now passes 70 command checks, exact whole-container export and
independent Save As identity checks. It covers thin32/64, fat32/64 swapped,
both saved slice indices, equal-address section domains, undefined calls,
big-endian inspection, Unicode paths, edit history, source removal and read-only
mutation refusal. All seven focused CLI suites pass (9.47s), including existing
ELF, ELF reference, binary, segmented, general and project CLI regressions:
`out/macho-task6-cli-regression.log`. Native metadata and slice controls remain
pending at this CLI checkpoint.
Engine19/cache8/reference7 identities remain unchanged.

Full CLI checkpoint gates subsequently passed: headless Debug92/92 (42.85s),
Release92/92 (28.49s), desktop Debug105/105 (58.10s). Desktop ran alone after
both builds and all other compiler/test processes ended. Logs are
`out/macho-task6-cli-full-debug.log`, `out/macho-task6-cli-full-release.log`,
and `out/macho-task6-cli-full-desktop-idle.log`. Existing warnings remain; no
assertions or timeouts were weakened. `out/macho-task6-cli-preservation-audit.json`
verifies all3130 historical/accepted-install records with zero mismatches.
This completes the CLI checkpoint only; Task6 native workflows and Task7
oracle/install/final review remain open, as does the full IDA-class objective.

Native Task6 implementation now provides an immutable worker-built prefix index
over26 metadata categories. Row lookup uses fixed-size category boundaries;
public pages are limited to256 rows and check bounds/cancellation. The native
virtual table renders indexed records on demand and exposes their physical
source records. Symbol activation uses declared section-domain addresses for
definitions and the original nlist record for other states. Selected-record
details remain readable in narrow panes. Universal Slice rows enable
"Open original slice in new tab", which imports the original source on the
worker with an explicit slice; existing project recipes/identities/edits remain
independent. Missing or changed source files are handled by the ordinary worker
import path; this action does not reinterpret a saved project.

The actual wxWidgets workflow first failed on absent nlist rows, then on the
missing slice control. The harness returns failure through OnRun (wx ignores
OnExit's return for process status). Focused native checks now pass for nonfirst
symbols and references, domain Follow, exact undefined-symbol source offsets,
both universal selections, user rename/comment/metadata patch/undo/redo,
byte-exact full-container export and unchanged source, independent Save As,
source-missing read-only reopen, PE/Mach-O tab switching, classic dyld and
chained import source activation, chained starts/pointers, encryption,
data-in-code and unauthenticated signature declarations. A real held analysis
completion verifies that background Mach-O publication cannot replace the
active PE tab's facts, selection, metadata or enabled actions. Unsupported
big-endian input retains native metadata without decoded facts. The final
focused run passed in2.87s (`out/macho-task6-native-held.log`). Worker page tests
extend `macho_project_symbols` with exact count, nonfirst-page identity/stride,
overflow/oversize/terminal bounds and cancellation checks in both widths.
Actual own-HWND normal/compact captures under
`out/build/windows-desktop/tests/artifacts/macho-{normal,compact}.png` were
visually inspected; compact metadata has room for the grid and selected details.
Full current-source gates remain pending at this point.

User-requested output cleanup removed1265 stale targets containing14791 files
(4.05GiB): obsolete build trees, old installation bundles, staging probes and
accumulated root logs. Only the two active build trees and latest validated
ElfDebug bundle remain, along with required tools, original compatibility
captures and the current Mach-O oracle evidence. Resolved paths were verified
inside G:/HexLab/out and reparse points rejected before deletion. The manifest
is `out/cleanup-2026-10-20.json`. Older log/probe paths in historical checkpoint
descriptions are historical evidence references; those staging artifacts were
removed under this explicit cleanup request. Sealed original captures and the
latest accepted inventory remain available for verification.

Task6 full current-source gates passed: headless Debug92/92 (69.52s),
Release92/92 (49.22s), desktop Debug106/106 (97.82s). The desktop suite ran
alone after both builds and all other compiler/test processes ended. Evidence:
`out/macho-task6-full-debug.log`, `out/macho-task6-full-release.log`,
`out/macho-task6-full-desktop-idle.log`; final process audit zero. All dependent
source consumers rebuilt. Existing warnings remain; assertions/timeouts were
not weakened. Post-cleanup preservation audit
`out/macho-task6-preservation-audit.json` verifies all3130 retained records
with zero mismatches. Task6 is complete; Task7 fresh independent oracle,
new installed distribution/SDK/offline/production/boundary verification and
one final whole-stage review remain required. Full IDA-class parity remains
an active objective beyond this Mach-O stage.

Task7 independent oracle is implemented in `tests/macho_oracle.py` and
`tests/macho_oracle_probe.cpp`, with original compiler/linker sources and
binary tool pins in `tests/fixtures/macho_oracle`. Fresh focused and full
headless runs compare36 selected-input projections over28 distinct files.
They include freestanding i386/x86-64/arm64 compiler objects; x86-64/arm64
provider dylibs and classic/chained consumer dylibs/executables; i386 scattered/
pair and x86-64 subtractor/PC-relative assembly relocations; a freshly compiled
data-region object; FAT32/FAT64 containers in both byte orders; thin literal
headers in both widths/orders; and an unknown-command partial case.

The comparison covers original header/command envelopes and physical source
records, segment/section scalar fields, nlist words and source locations,
LLVM-declared symbol names/values/domains, raw relocation words at LLVM-derived
locations, dynamic tables/indirect symbols, library paths/packed versions and
ordinals, classic dyld emissions/type/library/addend, exports, chained headers/
imports/starts/pages/raw pointers and static symbol/library/rebase association.
Twelve semantic projection forgeries are rejected. Missing tools, wrong tool
hashes and three malformed input classes must fail; unknown commands retain
explicit partial metadata. An input is never an executable command. A failure
removes any stale passing report and writes a failure report.

LLVM23.1.3 binaries were freshly hashed and verified. LLVM's Mach-O JSON mode
mixes structured and plain text, so the harness reads pinned structured text.
readobj masks CPU subtype capabilities, checked separately through objdump's
capability column. LLVM normalizes thin magic; byte order is separately asserted
from the literal/compiler-target expectation. LLVM does not recognize swapped
universal envelopes; those literal descriptor checks and exact selected-child
LLVM comparisons are recorded separately, not claimed as LLVM envelope support.
Its observed i386-linker rejection is an explicit checked limitation; i386
compiler objects still receive comparisons. These static projections do not
prove runtime linking, PAC behavior, input execution or full CPU decoding.

Current passing reports are under each build's `tests/macho-oracle/<config>`.
They record178 exact commands/output hashes, source/tool/probe/runtime/input
hashes, tool versions, negative checks and limits. Focused final Debug run
passed in3.36s (`out/macho-task7-oracle-final-focus.log`). Full headless Debug
93/93 (52.58s) and Release93/93 (31.37s) passed. Desktop full107 checks are
pending at this checkpoint; production/disconnected/new install/SDK/boundary
verification and one final immutable whole-stage review remain open.
No production interpretation, engine19/cache8/reference7 identity or historical
producer artifact changed in this oracle checkpoint.

Oracle checkpoint full gates subsequently passed: headless Debug93/93 (52.58s),
Release93/93 (31.37s), desktopDebug107/107 (65.13s), with desktop alone after
all builds/other test processes ended. Final process audit zero. Each of the
three configurations has a current passing report:36 projections/28 distinct
inputs/178 commands/12 negative semantic families. The report audit checks94
source/tool/probe/runtime/input identity records per configuration with zero
mismatches (`out/macho-task7-oracle-report-audit.json`). Retained historical
captures and ElfDebug inventory also retain all3130 recorded hashes
(`out/macho-task7-oracle-preservation-audit.json`). Full logs are
`out/macho-task7-oracle-full-{debug,release,desktop-idle}.log`.

Attempted removal of four superseded harness bring-up logs and the dated
one-use cleanup script was rejected by automatic approval review as blocked
by policy. These five files remain. The completed cleanup script now throws
before its obsolete retention rules, preventing accidental deletion of later
builds or bundles. The original cleanup manifest remains valid. Task7's oracle
item is complete. Disconnected/production/boundary checks, MachODebug
installation/public SDK/installed workflows and one final stage review remain
pending; the full objective remains active.

Task7 installed/public SDK validation now uses a fresh provisional
`out/install/MachODebug` Windows x64 Debug developer bundle. The previous
ElfDebug bundle was not overwritten. The standalone C++20 consumer in
`tests/sdk/macho` initially failed configuration against the absent prefix;
its successful build reads51 installed HexLab headers, zero private engine
source/build headers, and eight installed import libraries, verified from MSVC
dependency/link logs (`out/macho-task7-sdk-isolation-audit.json`). It exercises
defined/undefined thin32/64 calls, both indices in FAT32/FAT64-swapped inputs,
concrete durable recipe bytes, metadata pages/source indices, object domains,
reference namespaces and original relocation proof, direct public relocation
and dyld resolver APIs, metadata/user edits/history, unselected-byte handling,
container-kind invalidation/Undo, exact whole-container export, protected source,
independent Save As and source-missing read-only cache/annotation/history reopen.
Runtime bindings remain unresolved; pointer slots yield stored preferred values.
All eight loaded engine module paths are checked against installed bin. The
current successful SDK log is `out/macho-task7-sdk-final.log`; the consumer
reports its exact artifacts directory. Input files are never executed.

Installed verification in `tests/macho_install_tests.cmake` runs20 current
Mach-O engine suites, including65 historical cache checks,104 guard checks and
46 dyld provenance checks, then the36-projection independent oracle and70-command
CLI workflow. Validation executables are copied without DLLs and use installed
bin through the child PATH. The packaged oracle inventories the installed
runtime via an explicit optional `--runtime-dir`. The native workflow also
passes from the installed prefix. Basic installed distribution checks pass.
Actual `hexlab.exe` checks cover thin32, thin64 and a source-missing saved
FAT64 project, with domain-qualified Jump, eight engine/three wx module path
proofs and normal/compact own-window captures. The actual application's saved
project was opened normally; explicit read-only mutation refusal is SDK evidence.

Visual inspection found that CMake's startup state hid the native harness window:
PrintWindow returned success but the image was black. A new pixel assertion
produced a real failing installed workflow (visible0/iconic0; lit0/4560).
The harness now explicitly shows/renders only its own HWND without activation
and rejects blank images. The installed suite passes with this assertion;
normal1280x900 and compact900x620 native images were visually inspected and
show readable metadata/source/details. Evidence is
`out/macho-task7-capture-red.log` and `out/macho-task7-installed-final.log`,
with current PNGs in the bundle's `validation/macho/artifacts` and real
application PNGs in `validation/actual-application`. This is validation-harness
behavior; production engine interpretation is unchanged.

Fresh `out/build/macho-production` Release builds with BUILD_TESTING=OFF and
desktop disabled. Its actual PE dependency/export audit and the Debug bundle
audit pass for all eight engines (`out/macho-task7-boundaries`): declared engine
dependency direction, no wx/Qt/LLVM/foreign decoder dependency, three explicit
private workspace hooks in the developer build, zero such exports in production.
The production CLI passes the70-command Mach-O workflow plus existing binary
and segmented CLI workflows. Fresh headless `out/build/macho-offline` uses
both FetchContent disconnected flags and creates no dependency-fetch tree.
Its initial suite had one x86-16 CPU comparison timeout under the existing10s
limit. That read-only comparison passed in isolation in0.01s; a full unchanged
rerun passes93/93 (37.78s). The cause of the initial host delay is unproven;
no assertion or timeout was weakened. Initial/final logs are retained.

Current headless Debug93/93 (37.47s) and Release93/93 (26.38s) also pass after
the packaging changes. Desktop107 verification is pending at this checkpoint.
The bundle is provisional until final documentation/evidence inventory and the
single immutable whole-stage review finish. No engine19/cache8/reference7
identity or historical producer artifact changed during delivery validation.

Delivery checkpoint full gates now pass: Debug93/93 (37.47s), Release93/93
(26.38s), desktop107/107 (57.17s), disconnected93/93 (37.78s), with desktop
alone after all builds/other tests ended. The packaged SDK executable also
passes from `validation/sdk-tools`, resolving all eight DLLs from installed
bin (`out/macho-task7-sdk-packaged.log`). Public SDK source is included under
`validation/sdk-source/macho`. The bundle contains two applications, eight
engine DLLs, three wx DLLs, public headers/import libraries, licenses and
validation fixtures/reports/captures. Its complete file inventory is
`validation/install-inventory.json`; that file excludes itself from hashing.
The candidate remains subject to the one independent whole-stage review.

Five fresh oracle reports (headless Debug/Release, desktop, disconnected,
installed) each pass36 projections/12 semantic families and94 identity records
with zero mismatches (`out/macho-task7-delivery-report-audit.json`). Retained
old captures/ElfDebug still verify3130 records with zero mismatches
(`out/macho-task7-delivery-preservation-audit.json`). Delivery logs, binary
dependency/export reports, SDK isolation proof and failure/repair evidence are
copied into the bundle's `validation/delivery-evidence`. Its current validation
record includes the initial unchanged-limit CPU timeout and the capture RED;
neither was hidden or converted into a passing claim. Final stage review and
any material-finding fix pass remain open. The full IDA-class objective remains
active beyond this Mach-O delivery checkpoint.

## Final whole-stage review and engine20 correction

The one independent reviewer inspected an immutable513-file source snapshot and
905-file candidate (`out/macho-final-review/review.md`). Parent independently
verified both source copies and every candidate hash before mutation. One P2
was accepted: command/export anchor creation checked only the first fixed-header
byte, unlike the public dyld resolver. A malformed incomplete/discontiguous or
later-byte-aliased header could therefore publish false entry/export addresses
and function roots. One minor stale SDK-status paragraph was also corrected.
All12 declined judgments were individually adjudicated in `rulings.md`;
unsupported runtime semantics, broader IDA parity and fresh-machine deployment
remain explicit future obligations, not inferred support.

Before correction, genuine engine19 ran once against a copied matching runtime,
SDK and source in the new `out/macho-cache-v8-v19-capture`. Its617 sealed records
include the original project/input/producer and actual6175-byte derived payload
SHA789d2fd9e94dfe4fd9a3aab0be310083d742f4e41ca35c5b0567bd47536c1d8b,
2593-byte reference payload
SHAd7ed06bc907ddb10cf146d4083babaca3e59c265ba88428e0802b8ff35cc9579,
and enginec881c2f9fac59e81cefa6de6f7eddb4738a67b48a184f7527bd7af882e0b6ce5.
No cache header/key/checksum was rewritten. Promoted fixture bytes are unchanged.

A regression matrix covers both widths/orders, thin and explicit universal
index1, full/truncated/discontiguous/later-byte alias/compatible split mappings,
raw source declarations, loader/resolver agreement and false automatic roots.
Actual RED:180 checks/60 failures. One shared bounded cancellable header helper
now requires every fixed-header byte to map uniquely and contiguously; raw
unresolved declarations remain inspectable. Engine identity advances20;
derived/reference schema8 and reference payload7 are unchanged. GREEN:180
command checks and78 genuine old-cache checks across six producer generations.

Final current-source gates pass: headless Debug93/93 (39.36s), Release93/93
(27.26s), desktop Debug107/107 (57.79s, alone), disconnected93/93 (40.06s).
Production BUILD_TESTING=OFF rebuild,70-command Mach-O and legacy/segmented CLI
checks, and actual eight-DLL dependency/export boundaries pass. The developer
boundary also passes; production has zero private workspace test-hook exports.

MachODebug was restaged and verified against engine20. Standard installation,
20 Mach-O engine suites (including78 historical checks), independent36-view/
12-forgery oracle,70 CLI checks and18-phase actual native workflow pass.
Installed-header/import-library-only SDK and its packaged copy pass all eight
project cases plus direct relocation/dyld APIs and typed metadata checks;
MSVC trace audit confirms51 installed headers, zero private headers and eight
installed libraries. Actual packaged application thin32/thin64 and source-missing
saved FAT64 workflows verify Jump, own-window nonblank captures and all eight
engine/three wx DLL paths. The actual application opens the saved project in
normal read/write mode; the SDK/native harness explicitly verifies read-only
embedded reopen. Compact native and saved-app captures were visually inspected.

All five fresh oracle reports each verify94 source/tool/input/runtime identities
with zero mismatches (`out/macho-review-report-audit.json`). Six cache captures
and the accepted ElfDebug verify3747 preserved records with zero mismatches
(`out/macho-review-preservation-audit.json`). The initial cold offline timeout
and original black capture RED remain retained evidence; no timeout/assertion
was weakened. The final bundle inventory excludes itself and hashes every other
file, including current review/rulings/logs/audits. Validation evidence is under
`out/install/MachODebug/validation/delivery-evidence`.

The single review, one material RED/GREEN correction pass, full revalidation and
rulings close this Mach-O plan. The full IDA-class objective remains active;
ARM/Thumb/AArch64 decoding, richer types/stack analysis, decompilation, debugging,
plugins and further platform/delivery work remain unfinished.
