# Module dependency inventory

The command hexlab_cli modules <binary>... loads supplied images without
running analysis and prints direct dependency names from parsed metadata. PE
imports, ELF DT_NEEDED entries, and Mach-O dependency load commands are
included. Each name is resolved against other supplied file basenames using
case-insensitive matching. Supplied ELF files also advertise a unique,
unambiguous basename from their `DT_SONAME` entry as a provider alias, so a
renamed file can still match its declared shared-library name. Conflicting
distinct `DT_SONAME` values are ignored for that file. This alias match does not
establish ABI compatibility or loader precedence.

Use hexlab_cli modules --graph <root> <supplied>... to recursively display the
dependency graph reachable from the first supplied image. The root is also part
of the candidate set. Each graph node receives its zero-based position in the
input list. The identity table marks normalized duplicate paths separately
from distinct paths that share a basename. An edge reports an unresolved
name, ambiguous provider IDs, a cycle, an already-expanded node, or a depth
limit. Dependency names are ordered by case-insensitive basename and then
exact spelling; provider identities follow input order. Repeated normalized
paths remain visible as separate input rows, but resolve as one provider using
the first row's ID; only distinct normalized paths with the same basename are
competing providers. The graph stores references to shared immutable provider
buckets, so dependency edges do not each copy a bucket's IDs.

Graph mode is bounded to 4,096 supplied images, 100,000 raw and unique
dependency rows, 16 MiB of dependency-name bytes, and 64 recursive levels.
Ambiguous-provider ID display is capped at 100,000 IDs across the report. The
summary reports the number of expanded nodes and whether supplied files were
unreachable or beyond the depth limit. A fixed-size diagnostic rollup counts
unresolved and weak-unresolved edges, ambiguous edges, partial searches and
their unsupported/escaped/error path counts, incompatible providers,
depth-limited rows, cycles, and already-expanded edges. Counts cover reachable
rows displayed by the graph and are bounded by the graph row cap. Malformed or
missing images report the loader diagnostic and stop the command.

Without `--discover`, graph mode uses only the supplied file set. PE dependency
edges are case-insensitive and retain only providers with a compatible known
COFF machine and PE32/PE32+ class; rejected same-name providers are counted on
unresolved edges. Unknown machine IDs remain eligible because metadata cannot
establish a mismatch. ELF and Mach-O graph name matching (including ELF
`DT_SONAME` aliases) does not perform this PE-specific check. The graph does not
search host library paths or discover
additional files from disk. The one-shot command remains available without
the --graph switch.

For a bounded ELF search-path view, graph mode also accepts
`hexlab_cli modules --sysroot <directory> --graph <root> <supplied>...`.
With a sysroot, ELF `DT_RUNPATH` (when present) or otherwise `DT_RPATH`
entries are split on colons and `$ORIGIN`/`${ORIGIN}` are expanded relative
to the importing object's canonical directory. Candidate paths are
canonicalized and considered only when they remain below the supplied sysroot
and exactly identify another supplied file. A declared search path takes
precedence over basename matching; without one, existing supplied-basename
behavior applies. Other dynamic-loader tokens, environment variables,
inherited RPATH lookup, and filesystem discovery are not implemented by this
supplied-file path mode. This is a partial path-resolution aid, not full loader
precedence.

Add `--glibc-system-search` to explicitly include the target sysroot's glibc
cache and standard default directories in filesystem discovery:

```text
hexlab_cli modules --sysroot ./rootfs --discover --glibc-system-search --graph ./rootfs/bin/app
```

The cache reader opens only `<sysroot>/etc/ld.so.cache`, after canonicalizing
the sysroot and verifying the cache itself stays beneath it. The cache snapshot
is reused for the graph walk. This opt-in never reads the host cache or process
environment. Cache size and entry count are bounded. The new glibc cache
format 1.1 is supported; old and compatibility layouts, unknown byte order,
malformed entries, nonzero required OS versions, and hardware-capability
entries are reported as unsupported and cannot supply candidates. Cache ABI
flags are matched conservatively against the importer's ELF machine and class;
unknown machine-specific variants remain unsupported. Every cache path is
interpreted below the explicit sysroot and must canonicalize to a regular file
inside it.

The same opt-in searches `/lib` and `/usr/lib`, plus recognized multiarch
default directories for x86, AArch64, ARM, RISC-V, LoongArch, s390x, and
PPC64, all below the sysroot. Candidate rows retain whether they came from the
cache or a default directory. This is still an offline inventory: it does not
apply glibc hardware-capability precedence, secure-execution policy,
`-z nodefaultlib`,
or establish which duplicate file a real process would load. The CLI loads
candidate metadata without execution and rejects ELF class, byte-order,
machine, OSABI, or supported machine-ABI mismatches before adding graph nodes.
Without `--glibc-system-search`, the cache and standard directories are not
read or searched.

Examples:

    hexlab_cli modules app.exe vendor.dll
    hexlab_cli modules --graph app.exe vendor.dll helper.dll

## Opt-in ELF filesystem discovery

`hexlab_cli modules --sysroot <root-directory> --discover --graph <ELF-root>`
loads dependency metadata from exact filenames inside an explicit filesystem
root. Repeat `--search-dir <directory>` to add directories inside that sysroot.
Repeat `--ld-library-path-dir <directory>` to supply target
`LD_LIBRARY_PATH` entries for the graph walk. These are explicit host paths
inside the sysroot; HexLab never reads the host process environment. Both
directory kinds share the 128-entry bound.
The command never executes the binaries. It opens no ambient host library
paths and does not enumerate directory trees. Extra supplied files retain
input-order node IDs; discovered files follow in deterministic dependency and
search-directory order. Canonical aliases and symlinks to the same file share
one provider identity, and canonical paths escaping the root are rejected.

For basename dependencies, the importer contributes its own `DT_RUNPATH`, or
`DT_RPATH` only when no `DT_RUNPATH` entry exists. Absolute ELF directories
such as `/usr/lib` are mapped below the sysroot. `$ORIGIN` and `${ORIGIN}`
expand from the canonical importer's directory. Caller-supplied `$LIB` and
`$PLATFORM` values can expand anywhere in a path component. A supplied target
working directory resolves relative paths and empty search components. These
options make the assumed target environment explicit; HexLab does not guess
the target loader's token values.

The discovery API validates token forms in the original metadata string before
expansion. Unknown or malformed `$` tokens remain unsupported, while dollar
characters that are part of the canonical importer directory after `$ORIGIN`
expansion are treated as ordinary path characters. Expanded candidates still
must canonicalize to regular files beneath the explicit sysroot.

For recursive discovery, a `DT_RPATH` directory is carried to dependency
descendants when its declaring object has no `DT_RUNPATH`; `DT_RUNPATH` applies
only to that object's direct dependencies. If the same module is reached with
different inherited RPATH sets, discovery expands it once using the first
context and marks its outgoing rows partial instead of implying that both
contexts were resolved.
Unsupported ancestor `DT_RPATH` entries propagate as partial-search evidence
to descendant basename dependencies. A module's own `DT_RUNPATH` suppresses
its own `DT_RPATH` for both direct lookup and inheritance; it does not erase
RPATH entries inherited from its ancestors.

Caller-supplied `LD_LIBRARY_PATH` directories are considered after applicable
own/inherited `DT_RPATH` entries and before the current object's `DT_RUNPATH`.
Every compatible candidate is retained with `LD_LIBRARY_PATH` provenance,
including duplicates across directories; the inventory does not claim a
selected runtime provider. The user must provide each directory as a separate
`--ld-library-path-dir` argument. Entries are canonicalized, must be
directories beneath the sysroot, and cannot escape through symlinks.

```text
hexlab_cli modules --sysroot ./sdk --discover --target-cwd ./sdk/app \
  --ld-library-path-dir ./sdk/lib --lib-token lib64 --platform-token x86_64 \
  --graph ./sdk/app/bin/tool
```

The target working directory must be an existing directory inside the
canonical sysroot. `$LIB` and `$PLATFORM` values are limited to bounded ASCII
path-token characters. Expanded absolute paths are still canonicalized and
rejected if they escape the sysroot. Explicit search directories are
considered alongside dynamic paths. Every
matching compatible file from the supported search paths is retained; multiple
matches remain ambiguous rather than asserting dynamic-loader precedence.
Unsupported search paths and filesystem errors mark even resolved candidate
edges as partial searches. Only an edge with one
compatible provider is recursively expanded. `DT_NEEDED` absolute and leading
ORIGIN paths are also supported directly. Without an explicit target working
directory, ordinary relative paths and empty search components remain
unsupported. Unknown tokens remain unsupported.

Each candidate records its canonical path, discovery source and the dynamic
entry's file offset. `DT_NEEDED` provenance is printed for every discovered
dependency. Metadata is loaded with the existing document loader, then filtered
through the same ELF class, byte-order, machine, OSABI and supported
machine-specific ABI checks as supplied-symbol resolution. Rejected formats
and ABI candidates are reported explicitly. Malformed candidate files stop the
command with their loader diagnostic. Missing paths, rejected sysroot escapes,
unsupported path forms, filesystem errors and depth limits remain visible as
unresolved graph edges. The existing symbol report also includes the retained
discovered modules; it remains a supplied-candidate report rather than a
simulated runtime link map.

Discovery shares the 4,096-module, 100,000-dependency-row, 16-MiB-name and
64-level graph bounds. It additionally limits the entire traversal to 4,096
distinct inspected files, one million dynamic metadata entries, 100,000 exact
path probes, 100,000 candidate records and 16 MiB of candidate path bytes.
Each importer accepts at most 128 combined dynamic/explicit search directories;
individual metadata strings are capped at 32 KiB. Budget exhaustion reports a
limit error without silently truncating resolution. The analysis API
`discover_elf_dependency_files` exposes this bounded single-importer search,
its provenance and counters, inherited RPATH entries for caller-managed
traversal, and cooperative cancellation independently of the CLI.

ELF `DT_AUXILIARY` and GNU `DT_FILTER` names are also returned as separately
typed inventory rows with their own dynamic-entry offsets and bounded
sysroot-contained path candidates. CLI graph output labels them explicitly and
does not fold them into the `DT_NEEDED` dependency edges or recursively expand
their candidates. This records the declared names and candidate files only;
it does not model filter symbol lookup, auxiliary fallback, or loader ordering.

Mach-O `--discover --sysroot ... --graph` also walks `LC_LOAD_DYLIB`, weak,
reexport and upward load commands. It expands `@loader_path` relative to the
importer, `@executable_path` relative to a supplied root executable, and
`@rpath` against the accumulated `LC_RPATH` entries in traversal order. Absolute
install names are rooted below the sysroot; ordinary relative install names
are interpreted as sysroot-relative paths. Relative `LC_RPATH` values and
unknown `@` forms remain unsupported. No host dyld cache, default paths or
ambient directory scans are consulted. Every candidate is canonicalized and
must remain a regular file inside the explicit sysroot.

Mach-O discovery retains load-command kind, command index/file offset, the
candidate path source and the supplying `LC_RPATH` command offset. All
compatible candidate files are shown; multiple providers remain ambiguous.
Provider slices must match the root's CPU type and subtype, including selecting
the matching slice from a universal binary when available. Recursive traversal
is bounded by the same 4,096-file and 64-level graph caps, plus the API's
metadata/name/path/probe/candidate/RPATH limits. Cycles share canonical module
identity. If a file is reached with a different inherited `LC_RPATH` context,
it is expanded once using the first context and outgoing rows are marked
partial. Weak imports may remain unresolved without making the whole report
fatal; this inventory does not claim dyld runtime behavior.

The analysis API `discover_macho_dependency_files` exposes bounded single-image
path discovery, candidate provenance, inherited `LC_RPATH` state and
cooperative cancellation. It does not inspect binary symbols or claim that a
matching install name is ABI-compatible beyond the selected CPU slice.

The analysis API `discover_pe_dependency_files` provides a bounded PE
counterpart for caller-selected search directories: it checks the importer
directory and explicit directories, performs ASCII case-insensitive DLL leaf
matching, canonicalizes matches, and rejects files outside the sysroot. The
API caps dependency names, directories, enumerated directory entries, and
candidate paths and supports cancellation. Directory entries whose native
filename falls outside the accepted ASCII import-name subset are skipped
without converting through the host locale or failing the inventory. The
`hexlab_cli pe-deps` command
loads one PE image, reads its imports, and reports matching candidate files:

    hexlab_cli pe-deps --sysroot ./sdk --search-dir ./sdk/bin app.exe

Add `--windows-defaults` to append target-bitness-aware Windows defaults
inside the explicit sysroot. PE32 images use `Windows/SysWOW64` when present;
if that directory is absent, `Windows/System32` is used for a 32-bit Windows
sysroot. PE32+ images use `Windows/System32`. The API accepts an explicit
`PeDependencyTargetBitness`; callers that leave it unspecified retain the
legacy `System32` behavior. No host paths or environment variables are
consulted, and missing default directories are skipped. The inventory rank
keeps the order: importer directory, caller-supplied search directories in
argument order, the selected system directory, then `Windows`. Every matching file remains visible with its rank; the lowest rank
is marked effective and later ranks are marked shadowed. Multiple matches at
the effective rank remain ambiguous. Candidates within a directory rank are
ordered by exact ASCII leaf spelling, so case-colliding files do not inherit
the host filesystem's unspecified directory-iteration order. These ranks describe this offline
inventory policy and do not model KnownDLLs, API-set redirection, WOW64
filesystem redirection, side-by-side activation, already-loaded modules, or all
Windows loader search rules. The command never loads or executes candidates. Each deduplicated module row
also labels whether it appears in the PE's ordinary import table (`eager`) or
delay-import table (`delay-load`). If a library appears in both tables, the row
shows both labels. This is import metadata provenance, not a claim that a
particular delay-loaded symbol was invoked or resolved at runtime. The API
accepts parsed `ImportSymbol` rows to preserve these flags; its name-only
compatibility overload labels names as eager because it has no delay metadata.

It is an inventory primitive; API-set redirection, side-by-side activation,
and forwarding are not inferred.

This is an offline discovery policy. The target environment beyond the
explicit working directory and token values, loader cache, default system paths,
secure-execution rules,
link-map interposition, weak-zero/copy-relocation behavior, TLS/IFUNC execution,
relocation application, Mach-O dyld cache lookup, and default-path precedence
are not modeled.
Filesystem identity and case handling follow the host filesystem; this is not
a simulation of a target filesystem's case rules. Path checks describe the
files observed during the command, not a persistent filesystem snapshot.
The selected dynamic-entry/token meanings follow [Linux man-pages,
`ld.so`](https://man7.org/linux/man-pages/man8/ld.so.8.html); full loader search
precedence is outside the discovery inventory.

    hexlab_cli modules --sysroot ./sdk --discover --search-dir ./sdk/lib --graph ./sdk/bin/app

Repeated `DT_NEEDED` declarations are retained as separate rows, even when their names match. Each row keeps its own dynamic-table file offset and bounded candidate-resolution accounting, so a later duplicate cannot silently lose its provenance.
