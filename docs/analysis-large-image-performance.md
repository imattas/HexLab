# Large-image instruction fetch performance

Reachable analysis previously requested up to fifteen source bytes from the
image backing for every decoded instruction. The x86-64 path commonly decodes
one-byte NOPs, so a long linear code region caused one backing call per byte of
code even when the backing is a mapped file or a storage wrapper with expensive
per-call overhead.

`analyze` now owns a bounded 4 KiB instruction-byte cache. A refill is capped
at the current executable segment's initialized file extent and at
`Image::code_window`, so the cache never crosses a code exclusion, encrypted
range, ARM code-context boundary, zero-fill tail, or segment boundary. Every
cache use rechecks the virtual address's own code window; this matters when
different virtual mappings alias the same file bytes. Instructions that straddle
contiguous virtual segments are assembled from separate bounded windows. The
cache is local to an analysis invocation and retains one `ByteView`, with no
global lifetime or synchronization state. `decode_at` uses the same bounded
reader for its single request.

The `analysis` CTest includes an instrumented mapped-file microbenchmark over a
256 KiB linear x86-64 image ending in `RET`. It records wall time, total storage
calls, small (at most 15-byte) calls, and bytes requested while verifying that
all 262,145 instructions and normal string scanning complete. The pre-cache
reader issued one small backing call per decoded instruction; the regression
requires fewer than 32 small calls and fewer than 128 total backing calls. A
second fixture places an exclusion in the prefetched range and provides another
entry after it, checking that analysis stops at the exclusion and safely refills
for the later root. Wall-clock milliseconds are reported for local comparison,
not used as a brittle pass/fail threshold.

On the Windows x64 Debug build used for this change, the fixture completed in
7,666 ms with 187 total backing calls, 2 calls of at most 15 bytes, and 4,191,857
requested bytes. The pre-cache algorithm would have made 262,145 instruction
reads alone on this same fixture (plus the same string-scan reads); the cache
reduces that code-fetch component to sixty-five instruction-fetch refills.

This benchmark demonstrates the improvement in backing-call count for a
linear, instruction-dense image. It does not claim a specific speedup on every
mapped-file, compressed, remote, or branch-heavy workload. The 4 KiB cache
reduces per-read overhead; it does not remove the per-instruction segment and
policy checks or reduce the analysis snapshot's memory use.

Incremental recovery can also retain instruction facts across execution-context
or code-policy changes when the address-to-file mapping and loader metadata are
unchanged. It rechecks each reused instruction's current context and permission,
then rebuilds control-flow edges, ownership, blocks, functions, and references.
Changed contexts therefore decode only facts whose own context no longer
matches. String results remain reusable when the segment-to-file mapping is
unchanged, since string recognition depends on file bytes and virtual-address
annotation rather than processor mode or code policy.



String extraction now has an optional cumulative work budget, `AnalysisOptions::string_scan_work_budget`. It counts byte inspections across encoding passes, so one byte revisited by ASCII, UTF-8, Windows-1252, UTF-16, and UTF-32 passes consumes work for each inspection. The default is `size_t` maximum and preserves exhaustive behavior. A smaller budget ends scanning with a partial result (`complete=false`) and a warning diagnostic; cancellation remains independently available through the stop token. The option participates in the function-engine fingerprint so cached derived results cannot cross different work budgets.

Function recovery also accepts an optional `AnalysisOptions::progress` callback.
It receives `("instruction-discovery", completed_attempts, instruction_budget)`
at start and after each 1024 new/reused instruction attempts, then
`("complete", 1, 1)` after facts and dependencies are finalized. The budget is
a hard ceiling, not an estimate of remaining total work; discovery may end
before it. Returning `false` cancels recovery without publishing a partial
snapshot, and a thrown callback is returned as an error. When analysis runs in
a project worker the callback runs on that worker thread, so callers should
keep it short and marshal UI updates to the owner thread. The callback does not
participate in cache fingerprints. This gives hosts bounded coarse progress
and cancellation control without claiming a corpus-wide ETA.
