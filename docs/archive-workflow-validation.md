# Archive workflow validation

The COFF `archive link-pe` path selects AMD64 or ordinary ARM64 from the root
object and filters archive providers by that exact machine before fixed-point
selection. Its generic linker rejects mixed selected inputs and emits the
matching PE32+ machine/header. See [ARM64 COFF static linking](coff-arm64-static-linking.md)
for supported sections, checked relocation formulas and explicit unwind/import
gaps. This ARM64 increment has source review only; loader/CLI builds and output
validation remain pending, and no tests were run.

`hexlab_cli archive list <path>` prints every ar member with its stable zero-based member index, decoded name, size, and member kind. Special index and long-name-table records remain visible so indices match the loader's archive model. Diagnostics reported by the loader are printed after the listing.

`hexlab_cli archive extract <path> --member <index> --output <path> [--replace]` copies one regular member to the explicit output path. Output creation is exclusive by default, so an existing file is preserved; `--replace` opts into truncating/replacing that path. Special records and out-of-range indices are rejected, and the library's extraction-size limit still applies. The output filename is supplied by the caller; archive member names are never joined to an extraction directory.

`hexlab_cli archive open <path> --member <index> --project <path.hxproj> [--replace]` selects a regular member and imports it through the normal project actor. The project embeds the selected member bytes and resolves a durable image recipe from those bytes; the archive is not treated as a single image. Non-regular members and out-of-range indices are rejected before project creation. The command stages the selected bytes in a uniquely reserved system temporary file because the current project import request is file-backed. The temporary file is removed on both success and failure after import/save-as returns, while the resulting project retains its embedded input and the selected member name/index is reported to the caller.

The desktop workflow is available from **File > Browse ar Archive...**. The browser displays stable member indices, names, sizes, and special-record kinds; only regular members can be opened. Opening a member passes its bounded storage view through the normal workspace/project import path, so the resulting untitled project embeds the member and can be saved normally. Its provenance label includes the archive path and member name. No extraction temporary file is needed by the desktop workflow.

The CLI project-open path continues to stage the selected member to a unique system temporary file before importing it; cleanup occurs after the import/save operation completes.

The `archive_cli` test exercises extraction into a fresh path, refuses an existing file without changing it, replaces it only with `--replace`, and rejects an out-of-range member. The `project_cli` test generates an ar containing two ELF relocatable objects, checks stable member listing, opens the second member into a project, reopens that project and verifies its ELF identity, and checks out-of-range selection failure. Loader-level format bounds, malformed member extents, cancellation, extraction limits, and unsupported thin archives are covered by `ar_loader`.

`hexlab_cli archive link-exec <archive> --root-object <ET_REL> --entry <symbol> --output <ET_EXEC>` runs the same fixed-point member selector and relocation subset as `archive link`, then emits a static ELF64 x86-64 executable. The named entry must be a defined symbol inside merged `.text`. The output rebases defined symbols, writes `.text`/`.data` section addresses and RX/RW `PT_LOAD` segments, and applies the supported RELA relocations at those final virtual addresses. The default load base is `0x400000`; dynamic linking and runtime libraries are not added. As with ET_REL linking, only allocated `.text` and initialized `.data` are currently accepted; TLS, COMDAT, debug sections, and other object formats remain unsupported. `SHN_COMMON` symbols are coalesced into `.bss` with strong/common/weak precedence.

The same `link`, `link-exec`, and `link-audit` commands now accept ELF64 little-endian AArch64 roots and homogeneous selected members. No architecture flag is needed: the root's ELF machine selects the linker. AArch64 output handles direct branches, ADRP plus ADD/load data references, and supported absolute/PC-relative RELA fields; executable RX/RW segments occupy separate 64KiB-aligned regions. Unsupported relocations and out-of-range branches fail before output creation. See [AArch64 archive linking and validation](ar-archive-validation.md#aarch64-static-archive-linking) for supported relocation numbers, the ET_REL analysis-artifact limitation, pinned clang/LLD comparison, and remaining exclusions.

`hexlab_cli archive link-pe <archive> --root-object <COFF .obj> --entry <symbol> --output <PE .exe>` links selected AMD64 COFF archive members into a fixed-base PE32+ console image. Ordinary and BigObj object layouts participate in fixed-point selection and linking. AMD64 Microsoft import-object members generate grouped import descriptors, by-name or by-ordinal lookup entries, writable IAT slots, and function jump thunks; other import architectures and delay-import variants remain unsupported. Common external symbols (`SectionNumber == 0`, nonzero `Value`) participate in archive-member selection, coalesce by name into zero-filled `.bss`, and use natural alignment capped at 32 bytes; selected strong section definitions override them. Initialized `.text`/`.rdata`/`.data` and uninitialized `.bss` inputs are supported. Relocations stored inside `.bss`, weak-external aliases, TLS, unwind metadata, base relocations, and CRT startup remain unsupported.

The same generic COFF archive selector and `link-pe` route accept regular ARM64
BigObj object members, using the BigObj 32-bit section ordinals and 20-byte
symbol rows. ARM64 BigObj still follows the ordinary ARM64 section and
relocation subset; ARM64 import objects, unwind metadata, and ARM64EC/ARM64X
members remain unsupported.

`hexlab_cli archive link-macho <archive> --root-object <Mach-O .o> --entry <symbol> --output <Mach-O executable>` links bounded homogeneous little-endian x86-64 or ARM64 `MH_OBJECT` members into a static `MH_EXECUTE`. Initialized `__TEXT,__text`, optional `__TEXT,__const` and `__DATA,__data`, and zero-fill `__DATA,__bss` contributions are alignment-merged; the supported architecture-specific relocations can resolve symbols in each output section. The image has RX text, a read-only constants segment, RW data/BSS and a separate zero-fill stack, and an architecture-specific `LC_UNIXTHREAD` entry state. Other object sections, BSS-stored relocations, unsupported relocation types, and runtime/dynamic linking remain rejected. See [static Mach-O linking](macho-static-linking.md) for exact bounds.
