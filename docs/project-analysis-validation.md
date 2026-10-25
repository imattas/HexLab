# Project analysis validation

This stage provides original C++20 shared engines, a wxWidgets desktop, a CLI and a separate SQLite runtime. It does not establish IDA feature parity. Windows x64 is the tested host. The x86-64 scalar decoder is intentionally partial; broad processors/formats, types/ABI services, semantic IR, pseudocode, live debugging, a complete extension SDK and other hosts remain later work.

## Acceptance evidence

The following table maps the sixteen acceptance classes in the approved stage specification to named executable checks. These are behavior checks, not counts of implemented product features.

| Class | Evidence |
| --- | --- |
| 1. Embedded input and reopen | `project_input`, `project_cli`: empty/multichunk/Unicode input, streamed hash/materialization and source-missing reopen/export |
| 2. Identity and locations | `identity`, `identity_platform`, `core`, `project_schema`: SHA vectors plus Windows oracle, unsigned big-endian values, typed domains and text validation |
| 3. Malformed data | `project_schema`, `project_input`, `reference_cache`, `derived_cache`, `project_derived_cache`: identity/schema/count/chunk/hash/cache rejection and readonly preservation |
| 4. Recovery/publication | `project_crash`, `project_save_crash`, `project_history`, `patch_export`: synchronized helper termination before/during/after commit/publication and preserved destinations |
| 5. Ownership/errors | `sqlite`, `project_history`, `project_save_crash`, `project_jobs`: leases, readonly/busy/conflict/cancel and no false committed acknowledgement |
| 6. Function recovery | `functions`, `incremental`: literal loops/diamonds/calls/chunks/shared tails, exclusions/overlap/indirect/budget stops |
| 7. References | `references`, `reference_cache`, `desktop_graph`: operand evidence, import association/external identity, unresolved target and explicit user intent; checked x86 RIP-relative read/write targets and RV32/RV64 block-local AUIPC+ADDI addresses require a complete mapped range with matching segment permissions |
| 8. Graphs | `graphs`, `project_graph`, `desktop_graph`: independently checked topology, deterministic SCC layout with rank ordering, hostile labels/JSON/DOT, budget limits, real node/edge hit tests and rendering |
| 9. Persistent edits/history | `project_commands`, `project_history`, `project_cli`, `desktop_edit`: names/comments/bookmarks/decisions/references, grouped undo/redo/branching, failed-edit preservation |
| 10. Effective bytes | `overlays`, `effective_input`, `project_commands`, `project_listing`, `desktop_orphan`: aliased/storage/metadata edits, short reads, file-only recovery and orphan editing |
| 11. Incremental work | `incremental`, `derived_cache`, `project_derived_cache`, `project_analysis`: skipped decode and shared fact identities, conservative rebuild reasons and separate cache-validation counters |
| 12. Exact export | `patch_export`, `patch_export_hash`, `project_cli`, `desktop_edit`: complete expected-file comparisons, Windows SHA oracle and protected source/hard-link paths |
| 13. Isolated documents/jobs | `analysis_pool`, `project_jobs`, `document_manager`, `desktop_project`, `desktop_search`, `desktop_graph`: explicit barriers, epoch/source/presentation rejection, per-tab history/search/graph state and joined shutdown |
| 14. Native editing | `desktop_edit`, `desktop_close`, `desktop_orphan`, `desktop_graph`, `desktop_binary`, docking smoke tests: real dialogs/controls, selected clipboard bytes/text, save/export, Cancel/Discard/Save close handling and floating-pane regressions |
| 15. Delivery | Full Debug headless/desktop rebuilds, Release headless, fresh disconnected headless and production builds, `install_tests.cmake` and `project_install_tests.cmake`; results recorded below |
| 16. Search | `search`, `desktop_search`, `project_cli`: independent literal page oracle, masks, Unicode/UTF16, chunk/gap/overlay boundaries, effective-width signed/unsigned immediates, budgets/cancel/cursors and canonical navigation |

The complete current CTest registry is printed by `ctest --preset windows-desktop -N`. Individual source filenames provide the exact fixture details. Process-kill recovery is not a power-loss or storage-firmware test. No accessibility/high-DPI, large-corpus latency or non-Windows result is implied.

## Verified checkpoints

Full Debug consumer rebuilds passed 39/39 headless and 49/49 desktop checks (`out/project-graph-final-headless.log`, `out/project-graph-final-desktop.log`). All consumers were rebuilt together after public snapshot/worker payload changes. Mixing old executables with changed model DLLs is unsupported.

Actual native workflow captures were inspected under `out/build/windows-desktop/tests/artifacts/`: `project-editing-normal.png`, `project-editing-compact.png`, `project-graph-normal.png`, `project-graph-compact.png`. They come from the real wx views and original graph geometry. Compact Metadata and Output share a bottom dock row so the listing remains usable.

The fresh Debug install is `out/install/ProjectAnalysisDebug`. `tests/install_tests.cmake` checks tools, engine/import libraries, database/SQLite headers and notices, binary CLI behavior and actual installed GUI startup. `tests/project_install_tests.cmake` copies only validation executables to a directory without DLLs and puts installed `bin` first on the child PATH. It exercises the installed project CLI with a separate SQLite oracle, installed recovery helpers, and eight desktop workflow executables compiled from the same MainFrame components. Those native executables test installed engines/toolkit; their application entry points are test harnesses. The separately installed `hexlab.exe` is exercised by the startup/docking smoke check. Installed workflow output is `out/project-analysis-final-install.log`.

Final checks after the review fix passed: Debug headless 39/39 and Release headless 39/39 (`out/project-analysis-final-debug-release.log`); Debug desktop 49/49 (`out/project-analysis-final-desktop.log`); fresh disconnected headless 39/39 (`out/project-analysis-final-offline.log`). A fresh BUILD_TESTING=OFF Release build and the complete project CLI process suite passed (`out/project-analysis-final-production.log`, `out/project-analysis-production-cli.log`). Neither fresh headless tree acquired `_deps`; the production tree has no test executable targets. Export inspection found no private database/actor test checkpoints in its DLLs.

`out/project-analysis-binary-audit.log` records the installed engine dependencies: no engine imports wx. The actual packaged application was launched on a known PE fixture; `tests/installed_runtime.ps1` verified its loaded status and checked process module filenames for all eight HexLab/SQLite DLLs and all wx DLLs against installed `bin`. Captures `validation/actual-application/installed-normal.png` and `installed-compact.png` were inspected. The pinned wx build exposes generic panes through UI Automation, so this external check uses the readable status bar; native notebook and selection assertions remain in the wx workflow tests. This is not an accessibility certification.

One fresh independent read-only whole-stage review examined original persistence, analysis, actors, shared commands, CLI and desktop code with representative test inspection. It substantiated no material correctness/data-loss/lifecycle/stale-source finding and identified one minor: the chunks dialog promised clearing while validation rejected an empty list. That contract is fixed, including prefilled existing chunks. Failing then passing regressions cover restored recovery, unchanged function identity, undo/reopen/redo and the real native dialog. Final suites above include the fix. The reviewer did not rerun tests, audit vendored internals or validate untested hosts/performance.

No Git identity or commits exist in this workspace. Source and the task ledger are retained on the unborn development branch. This completes the project/interactive-analysis stage; the full capability goal remains active.

## Runtime behavior and limits

The pool has exactly two workers and bounded per-document requests. SQL connections remain on their actors. Worker tasks capture immutable data; publication checks document epoch, complete analysis source and any presentation revision. Read-only view jobs cannot cancel writer-owned analysis. GUI menu availability does not clone user state, read bytes or decode; accepted edits publish only after commit. Manual listing decode, search and graph layout run on the pool.

Search streams at most 64 KiB per read. Patterns have at most 4096 encoded bytes, pages at most 4096 matches, and retained history at most 100000 matches/4096 pages. Candidate and comparison budgets produce continuation, not a false complete result. Immediate matches require current decoded facts and retain partial-source coverage. Reference views use indexed pages of at most 256 displayed rows. Graph views use bounded original models and cull offscreen drawing; whole-corpus performance is not established.

Incremental recovery reuses unaffected decodes and immutable blocks/functions. Ownership/references rebuild conservatively. When the caller proves that dirty ranges cover every effective-byte difference, string refresh rescans each complete file-backed or unmapped scan domain that intersects the edit and retains records from other domains. This still handles unbounded runs exactly: the affected scan domain is rescanned to its established boundaries. Unverified ranges, incomplete prior results and mapping uncertainty retain the full-scan fallback. Cache loading intentionally validates more than a checksum and can still perform decoding/walking/scanning. Counters and reasons expose these costs.

## Effective-byte validation before incremental reuse

Incremental decode reuse now checks each otherwise eligible instruction's
encoded bytes against the current effective image before adding it to the
reuse table. A missing or incomplete dirty-range hint cannot preserve an old
CALL target, opcode or instruction length when those encoded bytes changed.
Rejected facts are decoded again if reachable; references and ownership are
rebuilt from that current walk. `rejected_reuse_instructions` counts prior
facts rejected by this source-byte check, separately from ordinary dirty-range
invalidations and successful reuse. Independent unchanged functions can still
retain their immutable records and skip decoding.

Callers that already compared both complete effective images and proved that
their ranges cover every byte difference can pass `byte_ranges_verified=true`
to `plan_invalidation`. That plan reuses facts outside the ranges without a
second read per instruction. This is a proof-bearing fast path: it must not be
set for UI patch hints, partial comparisons, or ranges that omit overlay or
loader-generated differences. The default remains defensive byte validation.
`validated_reuse_instructions` reports how many instruction facts took that
defensive comparison path, so callers and benchmarks can distinguish a proven
range-based pass from a byte-by-byte verification pass.

The project worker uses this fast path after `effective_changes` compares the
current effective image against the prior one inside the union of all patch
extents. Patch overlays cannot differ outside those extents, so the resulting
ranges cover the complete effective-image diff. This proof also allows local
string-domain refresh while leaving direct analysis API callers on the full
string-scan fallback unless they provide the same complete coverage proof.

A changed byte revision with no invalidation ranges explicitly falls back to
full code and string analysis, with the reason `Byte revision changed without
invalidation ranges`. This protects strings and other derived facts when no
change domain is available. Revision-only no-op transitions can consequently
perform extra work. Annotation-only requests under the same source key retain
the existing zero-decode sharing behavior. Backwards revisions remain invalid,
including requests that would otherwise take this fallback.

Cancellation is checked before and after each effective-byte reuse read. A
stop requested by the byte source during validation returns a canceled result
without exposing a partially prepared proposal or changing the prior snapshot.
The `incremental` regression fixture checks an undeclared CALL edit against a
fresh analysis, old-callee/reference removal, independent function reuse,
missing-range string rescanning, backward-revision rejection and deterministic
cancellation during source reads.

This check validates encoded instruction bytes; it is not a replacement for
complete loader-metadata invalidation ranges or a full source-difference scan.
Callers must still supply current parsed metadata, immutable images and
accurate source revisions. The defensive default adds one bounded read per
instruction considered for reuse; complete-diff callers can avoid those reads.

The dependency index stores fact read ranges sorted by start, with a prefix
maximum end. A changed range binary-searches the earliest prefix that could
overlap it, scans only candidate intervals, then follows the existing
transitive prerequisite edges. Index construction sorts all recorded intervals;
overlapping long ranges can still make an individual lookup scan many
candidates. The immutable project analysis basis keeps a lazy, thread-safe index
cache, so canceled/retried plans for the same basis do not sort the same fact
graph again. Direct callers that construct a basis without a cache retain the
existing local-index fallback. Large-project performance remains unmeasured.

Execution-context and code-policy updates can reuse old instruction facts when
the source mapping and loader metadata stay fixed. Recovery verifies each
instruction against the new per-address context and permission before reuse,
then reconstructs flow edges and all dependent ownership and function facts.
This means a context change does not reuse stale edges or facts at addresses
whose decode context changed. String results are retained when the segment
mapping is identical, because their byte scan and address annotation do not
depend on processor context. Source identity, loader metadata, or address
mapping uncertainty continues to require full invalidation.

Windows/MSVC Debug validation used the fresh task-specific build below:

```powershell
cmake -S . -B .codex-incremental-source-proof-build -G "Visual Studio 17 2022" -A x64 -DHEXLAB_BUILD_DESKTOP=OFF -DBUILD_TESTING=ON -DHEXLAB_ENABLE_PINNED_LLVM_ORACLES=OFF
cmake --build .codex-incremental-source-proof-build --config Debug --target hexlab_incremental_tests hexlab_project_analysis_tests hexlab_project_jobs_tests hexlab_project_derived_cache_tests --parallel 4
ctest --test-dir .codex-incremental-source-proof-build -C Debug -R '^(incremental|project_analysis|project_jobs|project_derived_cache)$' --output-on-failure
```

All four CTests passed, including project publication, actor cancellation and
derived-cache integration checks.
