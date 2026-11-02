# PE volatile metadata

`PeLoadConfiguration::volatile_metadata` exposes a bounded inventory of compiler
volatile-access instruction RVAs and code ranges covered by that inventory.
The existing `volatile_metadata_rva` and `volatile_metadata_source` retain the
normalized pointer and its load-config field provenance. The pointer is a
preferred-base VA at PE32 offset 160 or PE32+ offset 256; the nested table
locations and row targets are image RVAs. Rebasing does not change those RVAs.

The parser is `libs/loaders/src/pe_volatile.cpp`. It reads the 24-byte fixed
header and retains declared size, raw version DWORD, both table RVAs and both
byte sizes. Raw `Version == 1` is exposed as the legacy encoding. Other values
are interpreted as the newer packed pair of 16-bit minimum and maximum version
fields, following the layout used by LIEF's current parser. The API preserves
both words exactly and does not assign undocumented flag or compatibility
semantics to them. Both encodings use the same table validation below. A
declared extension is source-backed but remains opaque.

The access table consists of 4-byte instruction RVAs. The range table consists
of 8-byte RVA/size pairs, with a half-open target extent `[rva, rva + size)`.
Each instruction must address initialized executable bytes. Each nonempty
range must fit entirely within initialized executable mappings, including
validation across mapping boundaries. Zero-filled tails, non-executable data,
unmapped holes, empty range rows and image overflows are malformed.
The parser does not decode an instruction or infer the width/type of its
memory access. Input order, duplicate instructions and overlapping ranges are
preserved. It makes no claim that every instruction lies inside a range row.

## Bounds and diagnostics

- The header must be at least 24 bytes and at most 1 MiB. The full declared
  header extent must be initialized, but only 24 bytes are materialized.
- Table sizes must be divisible by 4 and 8 respectively. Their aggregate
  encoded size is capped at 16 MiB and their aggregate row count at 1,000,000.
- Nonempty tables require nonzero RVAs and fully initialized source extents.
  Empty tables retain their raw RVA without dereferencing it.
- Target mapping traversal is capped at 1,000,000 aggregate steps. All RVA,
  table-row and target-end calculations use widened arithmetic.
- Both decoded row vectors publish together only after complete validation.
  A failure in either table leaves both vectors empty. Header fields and any
  validated source spans remain available.
- `source` covers the full validated header extent, or its known 24-byte prefix
  when the extension extent is malformed. Table sources and each row's indexed
  source cite original file spans; bytes are not copied into the metadata.
- `decoded`, `unsupported`, `malformed` and `resource_limit` distinguish results;
  unsuccessful results carry a diagnostic. Cancellation propagates to the
  caller instead of being converted into metadata.

A short load-config structure or a zero pointer yields no nested object.
An invalid nonzero pointer yields a malformed object with a diagnostic naming
the raw preferred-base VA. Pointer normalization and payload parsing have a
local diagnostic boundary, preserving unrelated load-config fields.
Allocation failures still follow the loader's outer resource-limit handling.

The CLI prints status, raw and interpreted version fields, table counts,
diagnostics and up to 256 rows from each table. Each row includes its target RVA
and source file offset when available; omitted rows are reported. Desktop PE
metadata pages do not yet render these records.

This is an inspection capability. It does not select runtime memory ordering,
emulate acquire/release semantics, prove a compiler's inventory complete, or
execute target instructions. Hot-patch metadata and language-specific unwind
handler execution remain separate residual work.

## Format references

[Microsoft's `/volatileMetadata` reference](https://learn.microsoft.com/en-us/cpp/build/reference/volatile?view=msvc-170)
describes the metadata's role in x86/x64 emulation on ARM64. The legacy header,
RVA rows and range rows follow the
[FEX Windows image definitions](https://github.com/FEX-Emu/FEX/blob/main/Source/Windows/include/winnt.h)
and their image-relative use in
[FEX's image tracker](https://github.com/FEX-Emu/FEX/blob/main/Source/Windows/Common/ImageTracker.cpp).
[LIEF's parser](https://github.com/lief-project/LIEF/blob/main/src/PE/LoadConfigurations/VolatileMetadata.cpp)
documents the newer min/max-version field layout. HexLab follows only that
field layout; it preserves raw words and makes no claim about their runtime
semantics.

## Verification record

Session constraint: no tests added or run. From the isolated worktree
`G:/HexLab/.worktrees/pe-volatile-metadata-nov02`, Windows MSVC 19.44.35229.0:

```powershell
cmake --preset windows-headless -DBUILD_TESTING=OFF
cmake --build out/build/windows-headless --config Release --target hexlab_loaders --parallel 2
```

Both commands exited 0 and `hexlab_loaders.dll` linked successfully. The cache
confirmed `BUILD_TESTING=OFF` and `HEXLAB_BUILD_DESKTOP=OFF`. Existing MSVC
DLL-interface and deprecated `u8path` warnings remain in unrelated sources.

WSL Ubuntu 24.04 / Clang 18.1.3:

```sh
cd /mnt/g/HexLab/.worktrees/pe-volatile-metadata-nov02
cmake --preset linux-headless -G "Unix Makefiles" -B /tmp/hexlab-pe-volatile-nov02 -DBUILD_TESTING=OFF
cmake --build /tmp/hexlab-pe-volatile-nov02 --target hexlab_loaders --parallel 2
```

Both Linux commands exited 0 and `libhexlab_loaders.so` linked successfully.
The cache confirmed Debug, `BUILD_TESTING=OFF` and `HEXLAB_BUILD_DESKTOP=OFF`.
Existing missing-field-initializer warnings remain in unrelated sources.
The initial Ninja preset configure failed because
Ninja is unavailable. A subsequent Make configure in Windows-mounted output
was interrupted during slow generation before compilation; the final build
uses native Linux output. No source workaround was required.

Windows configure/build logs are `configure-pe-volatile-windows.log` and
`build-pe-volatile-windows.log` in the worktree (ignored scratch files).
Linux logs are `/tmp/hexlab-pe-volatile-configure.log` and
`/tmp/hexlab-pe-volatile-build.log` in Ubuntu; copies are retained in the
worktree as `configure-pe-volatile-wsl-native.log` and
`build-pe-volatile-wsl.log`.

Source review covered complete-field gating, pointer failure isolation,
unknown versions/extended headers, widened extents and unmapped/uninitialized
targets, atomic publication after second-table failure, and cancellation.
This is build and source-review evidence; it provides no runtime parser-test
or emulator-behavior claim.

Follow-up source change adds the packed min/max version-word presentation and
CLI row summaries. Its isolated Windows and Ubuntu-24.04 configurations
succeeded with `BUILD_TESTING=OFF`; duplicate cold dependency builds were
stopped at integration request before reaching the loader/CLI targets. No tests
were added or run for this follow-up.
