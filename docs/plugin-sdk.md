# Native plugin SDK

## External CMake projects

HexLab installs a relocatable `HexLabPluginSdk` CMake package alongside the
public ABI headers. An external module can call
`find_package(HexLabPluginSdk CONFIG REQUIRED)`, link the
`hexlab::plugin_sdk` interface target, and include
`${HexLabPluginSdk_PLUGIN_PACKAGE_HELPER}` to generate and install the plugin's
`.hexlab-plugin` sidecar. The package includes a same-major-compatible version
file and the packaging helper, so the example does not need a source checkout.
See [`examples/plugins/minimal-cpp`](../examples/plugins/minimal-cpp/README.md)
for a complete action plugin and build/install commands. The standalone [`examples/plugins/flat-image-loader-cpp`](../examples/plugins/flat-image-loader-cpp/README.md) module demonstrates the optional ABI 1.10 loader image callback with a bounded magic probe, exact input reads, cancellation, and a single flat mapping. The standalone [`examples/plugins/debugger-processes-cpp`](../examples/plugins/debugger-processes-cpp/README.md) module shows RAII ownership and paged process enumeration through `DebuggerClient`.

The standalone [`examples/plugins/project-annotation-batch-cpp`](../examples/plugins/project-annotation-batch-cpp/README.md) analysis provider demonstrates the ABI 1.5+ atomic annotation batch through `ProjectClient`: it reads an edit revision, selects a function, then applies a rename and bookmark together. A stale revision rejects the batch without partially applying edits.

Native modules include `hexlab/plugins/sdk.h` from C or `sdk.hpp` from C++. The public ABI is a versioned C ABI: `HexLabPluginApi`, `HexLabHostApi`, and the project service table contain fixed-width integers, borrowed strings, opaque contexts, and C function pointers only. `HEXLAB_PLUGIN_QUERY_SYMBOL` is the exported entry-point name. Modules negotiate the major version during query; minor version and `struct_size` permit append-only growth. The SDK does not pass C++ objects, exceptions, or allocator-owned containers across the module boundary.

`sdk.h` provides `HEXLAB_PLUGIN_HAS_FIELD(table, TableType, field)` for every
versioned table. It handles null pointers, reads `struct_size` once, and checks
the requested field extent without overflowing size arithmetic. Use it before
reading optional callbacks or table tails; a present field can still be null
when that callback is optional. The C++ `ProjectClient`, `DebuggerClient`,
`ActiveDocumentClient`, `ActiveProjectBreakpointClient`, and
`ActiveDebuggerClient` use the same helper internally. For example:

```c
if (HEXLAB_PLUGIN_HAS_FIELD(host, HexLabHostApi, register_processor_extension) &&
    host->register_processor_extension) {
    /* register an optional processor extension */
}
```

This makes source compiled against a newer SDK safe to run with older hosts:
the descriptor's reported size, rather than the SDK header's current size,
decides whether an appended field may be read.

The C++ debugger-rule wrappers check each field's extent before loading its
callback pointer. They do not convert function pointers to object pointers,
so the public header also compiles with standard C++17 GCC.

ABI 1.4 keeps the legacy string `capabilities` array intact and appends an optional `declared_capabilities` table to `HexLabPluginApi`. Each `HexLabCapability` names a service contract and declares its own nonzero major version, minor version, and flags. Hosts read the table only when `struct_size` covers both appended fields, validate bounded IDs and unique declarations, and copy it into `PluginInfo`; ABI 1.0–1.3 modules therefore remain valid. Unknown IDs and versions remain descriptive metadata: a host does not infer support for a newer contract from a matching string. The C SDK offers `HEXLAB_PLUGIN_API_INITIALIZER_V14`; the original initializer remains source-compatible.

Capability consumers can call `PluginManager::supports_capability(plugin_id, capability_id, major, minimum_minor)`. It matches the exact major version and accepts a declaration whose minor version is at least the requested minimum; this treats minor revisions as backward-compatible within a capability contract. Legacy string labels never satisfy this query.

The desktop Plugins panel shows each versioned capability as `capability.id@major.minor` alongside legacy labels, making the actual extension contract visible during load and review.

For C modules, define `hexlab_plugin_query` with `HEXLAB_PLUGIN_EXPORT`, populate the descriptor with `HEXLAB_PLUGIN_API_INITIALIZER`, and implement `start`/`stop`. C++ modules can use `hexlab::plugins::sdk::make_api` to produce the identical C layout. Link the CMake interface target `hexlab::plugin_sdk` for the public include path; host applications use `hexlab::plugins::PluginManager` from `hexlab::plugins` to load modules.

On Windows, the host opens a plugin with `LoadLibraryExW` and restricts
dependent-module lookup to the plugin module's directory plus Windows' default
system directories. The process working directory is not searched for plugin
dependencies. Package private DLL dependencies beside the plugin module (or in
a standard system location); do not rely on the application's current
directory. This narrows accidental DLL preloading, but native plugins and their
dependencies still execute in-process with the host's privileges.

The host initializes the `start` output instance to null before calling the callback. A nonzero return means initialization failed; the host then calls `stop` exactly once before unloading the module, passing the value left in the output slot. The value can be null, so `stop` must accept null and release resources acquired before the failure. The module must keep the stop callback and its code valid until that cleanup call completes.

The host also catches C++ exceptions raised by a native module's query, start,
action, loader, processor, analysis provider, or stop callback. Query and start exceptions become
I/O errors; action, loader, and processor exceptions follow the same callback
failure paths as invalid callback results. A stop exception is contained during
unload: registrations and project handles are still cleared and the module is
still closed. Plugins should return status codes instead of throwing, and a
throwing `stop` callback may still leave plugin-owned resources unreleased.

ABI 1.1 appends an optional `project_api` pointer to `HexLabHostApi`; older action-only plugins remain valid. A plugin must check `host->struct_size` before reading the pointer and tolerate a null pointer. The table has its own `struct_size` and `api_version` fields. It supports project create, open, close, analyze, summary, and paged function queries. Create accepts automatic format selection and PE, ELF, or Mach-O explicitly. Archive and raw imports are omitted because the table currently requires a single mapped image and raw loader options need an architecture-specific profile.

ABI 1.28 appends `undo` and `redo` to `HexLabProjectApi`, preserving the entire
preceding table prefix and `HEXLAB_PROJECT_API_VERSION` 1. Check `struct_size`
through the desired callback, or use `ProjectClient::supports_history()` and
the C++ `undo(expected_edit_revision)`/`redo(expected_edit_revision)` wrappers.
The host declares `project.history` v1.28 for modules requiring this contract.
Pass `HexLabProjectSummary::edit_revision` from a current summary; each call
moves one durable workspace history group using the same project path as native
automation. Adjacent steps with the same nonzero group ID move together; an
ungrouped step moves alone, and an atomic annotation batch stays intact.
A successful change
can invalidate derived facts and prior entity IDs; read a new summary and
refresh or analyze before consuming those facts.

ABI 1.29 appends `function_owners` to `HexLabProjectApi` and declares the
`project.function-owners` v1.29 capability. The paged query maps one address to
every recovered function that owns it, returning stable function IDs and entry
addresses. This preserves shared-tail ownership instead of forcing a provider
to guess which function a block belongs to. Each output record is
`HexLabFunctionOwner` and is size-checked like other append-only records. Its
IDs are tied to the current derived analysis and can expire after analysis is
replaced or the project is reopened. `ProjectClient::supports_function_owners`
and `function_owners` provide the C++ wrapper; older host tables remain valid
and report the capability as unavailable.

ABI 1.30 appends `instructions_text` and `block_instructions_text` to
`HexLabProjectApi` and declares `project.instruction-text` v1.30. These pages
return the same address and bytes as the original instruction callbacks, with
`HexLabInstructionText.text` holding up to 1023 UTF-8 bytes plus its terminator.
The ABI 1 `HexLabInstruction.text[256]` record and its callbacks keep their
original layout and behavior. Use `ProjectClient::supports_instruction_text()`
and the two `*_text` page methods; the C++ wrapper size-initializes the output
records. The CFG report example requires this capability and consumes the
extended block-instruction pages.

ABI 1.32 appends `strings_text` to `HexLabProjectApi` and declares the
`project.string-preview` v1.32 capability. Its `HexLabStringText.preview`
buffer carries up to 1023 UTF-8 bytes from the analysis preview. The original
`HexLabString.preview[256]` layout and `strings` callback remain unchanged.
Use `ProjectClient::supports_string_preview()` and `strings_preview()` to query
the larger page; old host tables report it as unavailable. The CFG report
example pages a bounded sample of these larger previews.

The result is `HEXLAB_PROJECT_HISTORY_OK` (0), `INVALID` (-1) for an invalid or
closed handle, `FAILED` (-2) for a read-only handle, an unavailable history
step, wrong owner thread, or another project failure, and `STALE` (-3) for an
edit-revision conflict. The full constant names use the
`HEXLAB_PROJECT_HISTORY_` prefix. Revision validation occurs before moving
history and again at the database transaction, so another connection's edits
cannot be silently undone against an obsolete snapshot. A stale request keeps
the history position unchanged. Call summary again after success before
issuing the inverse operation. Callbacks use the existing per-plugin handle
ownership, serialization, and exception containment; they do not affect the
desktop-owned active project unless that is the saved project explicitly
opened by the module. Read-only history listing/preview and history state
notifications are not yet exposed by this C ABI.

ABI 1.13 appends native type authoring callbacks to `HexLabProjectApi`: `import_header`, `types`, and `assign_type`. Check the table's `struct_size` through each callback before using it. Header import accepts at most 4 MiB of bounded C declarations and stores typedefs, struct/union/enum tags, global object types, and function prototypes in one atomic project command. Enumerator names and exact signed numeric values remain inside the enum type body. Identical reimports succeed without adding redundant history. There is no implicit filesystem or include resolution. Null options derive pointer width from the primary 32-bit or 64-bit project address space: ILP32 for 32-bit images, LLP64 for PE64, and LP64 for other 64-bit images. Other target models require explicit scalar byte widths in `HexLabHeaderImportOptions`; callers may override the inferred model. Legacy `types` pages keep their original layout and logical row set: only `DeclarationKind::type` definitions participate in paging, so imported object/function declarations do not alter ABI 1.13 indices. ABI 1.14 `declarations` pages include all three roles. `assign_type` assigns/removes a declaration's type at a mapped address through normal project history. Imports and assignments require writable project handles. Header replacement planning carries the complete expected destination row; a changed type body, name, origin, or declaration role rejects the import as a conflict instead of overwriting a newer edit.

ABI 1.35 extends `HexLabHeaderImportOptions` with `long_double_bytes` and explicit floating-point alignments. The fields are an optional struct tail, so callers that provide the older struct size remain accepted. A zero `long_double_bytes` selects the host's model default; zero alignment uses storage width. Non-power-of-two floating storage sizes require an explicit power-of-two alignment. Check the host's `abi_minor` before relying on the extended layout controls.

ABI 1.14 appends `declarations` and `enum_values`, preserving every ABI 1.0-1.13 table prefix. `HexLabDeclarationRecord` adds a durable role (`TYPE`, `OBJECT`, or `FUNCTION`) and enum constant count. `enum_values(type_id, start, capacity, ...)` pages through exact stored enum name/value pairs, including named enum references, with signedness and 64-bit two's-complement value bits. Initialize every output record's `struct_size`. Object/function declarations carry no inferred runtime address; address assignment is explicit. `HexLabHeaderImportSummary.imported_types` keeps its ABI 1.13 typedef-plus-tag count; object/function rows are visible through declaration pages. `types::format_enumerators` formats exact stored values in signed decimal notation when appropriate.

`examples/plugins/type-workflow` is a standalone C analysis-provider module demonstrating the complete flow: open a saved project writable, import embedded mutually-referencing C declarations, page through the resulting durable definitions, and report them. Build it with CMake and run its `import-c-types` provider against a saved project. The callback doesn't select an assignment address; real tools can use the listed IDs with `assign_type` after selecting an address in their own UI.

ABI 1.3 appends optional `register_loader_extension` and
`register_processor_extension` callbacks to `HexLabHostApi`. Check
`host->struct_size` through the desired callback field and check that the
pointer is non-null before use; ABI 1.0–1.2 modules remain loadable. Each
extension descriptor has its own `struct_size` and must use
`HEXLAB_EXTENSION_API_VERSION`. Registration validates the full descriptor,
non-empty bounded identifiers, callback pointer, and per-plugin extension
limit. Duplicate extension IDs within the same extension kind are rejected.

Loader extensions register a stable extension ID and format ID plus a bounded
probe callback. The host passes at most 4096 initial bytes and the total input
length; callbacks return decline/claim/error and a confidence score from 0 to
1000. `PluginManager::probe_loaders` dispatches every matching probe and picks
the highest-confidence claim, preserving registration order for ties. Processor
extensions register stable architecture and mode IDs and a decode callback.
`PluginManager::decode_processor` dispatches matching decoders with at most 32
bytes and accepts a bounded generic instruction record (length, flow kind,
mnemonic, and operand text). A claimed result must have a complete output
record, a length from 1 through the supplied byte count, a known flow value,
zero reserved bits, and NUL-terminated mnemonic and operand buffers. Invalid
records and callback failures quarantine the offending extension for the
lifetime of that manager. Dispatch continues to other matching extensions; if
none claims the request, the host falls back to its built-in decoder. Both
methods return an empty optional when no extension claims the request. The
manager's `extension_failures()` API reports quarantined IDs and reasons.

Extension descriptors are copied into the owning plugin context. Their
callbacks and extension contexts must remain valid until `stop` returns. A
manager lock keeps dispatch callbacks from racing unload; after `stop`, the
host clears registrations before closing the module. These are in-process
native callbacks and are not sandboxed. Loader probes select a plugin format
handler; the optional ABI 1.10 image callback constructs validated core images.
Processor decoders provide generic display records and the optional semantic
callbacks described below provide typed instructions for analysis.

ABI 1.9 appends `register_analysis_provider` to `HexLabHostApi`. A provider
descriptor is versioned independently with `HEXLAB_ANALYSIS_PROVIDER_API_VERSION`
and carries an ID, display name, opaque context, and report callback. Registration
is accepted only during `start`; IDs must be non-empty and unique per plugin.
`PluginManager::analysis_providers` exposes registered providers and
`run_analysis_provider` dispatches one by exact plugin/provider ID against an
existing project file. The host verifies the path, serializes invocation against
unload, supplies the host project API, and provides a zeroed 16 KiB output
buffer. The callback returns zero on success and must NUL-terminate its report;
nonzero status or an unterminated result is rejected. Providers should open the
project read-only using `project_api->open(..., 1, ...)`, query bounded pages,
and close the handle before returning. The desktop Plugins panel lists providers
and runs a selected provider against the project path entered in its Project
file field. These callbacks run in-process and are not sandboxed.
`examples/plugins/project-report` is a standalone C module that reports the
project input size, analyzed function count, and instruction count through this
provider route. Build it with CMake, load the resulting module in the desktop
Plugins panel, enter a saved `.hxproj` path, select `project-summary`, and run it.

The standalone examples also produce installable plugin packages. Configure an
example directory with CMake, build it, then run `cmake --install <build-dir>
--prefix <plugin-root>`. The install tree places the native module and its
`.hexlab-plugin` identity sidecar together under
`<plugin-root>/lib/hexlab/plugins/`. Pass that directory to
`PluginManager::scan_directory` or the desktop **Scan Directory...** action;
the sidecar lets the picker show the declared ID, name, and version before the
user chooses to load the module. The sample sidecars intentionally declare no
versioned service capabilities because these example binaries currently expose
only legacy string labels or register runtime services without a declared
capability table. The metadata remains advisory and is checked against the
loaded module identity after explicit load.

```c
static int32_t report(void *ctx, const HexLabProjectApi *api, const char *path,
                      char *out, uint32_t capacity) {
    (void)ctx;
    void *project = NULL;
    if (!api || !api->open || !api->close || !api->summary ||
        api->open(api->host_context, path, 1, &project) != 0) return -1;
    HexLabProjectSummary summary = { .struct_size = sizeof(summary) };
    const int status = api->summary(api->host_context, project, &summary);
    api->close(api->host_context, project);
    if (status != 0 || capacity < 2) return -1;
    snprintf(out, capacity, "Functions: %llu\\nInstructions: %llu",
             (unsigned long long)summary.function_count,
             (unsigned long long)summary.instruction_count);
    return 0;
}
```

## Durable breakpoints in the active saved project (ABI 1.18)

ABI 1.18 appends `active_project_breakpoint_api` to `HexLabHostApi`; older host-table prefixes and plugin binaries remain valid. The C table provides `snapshot`, bounded `query`, and `set` callbacks. `HexLabActiveProjectToken` binds each operation to the active document/open generation, project identity, and project generation. Obtain a fresh token with `snapshot`, then pass that same token to each query or mutation. A tab switch, project replacement, or intervening project edit makes it stale. Queries accept pages of 1–4096 records. `set` upserts by address or removes by address; valid sizes are 1, 2, 4, or 8 bytes, and execution breakpoints require size 1. Adds and updates must map every requested byte into the active image. Mutations are submitted through the normal workspace project command and history path.

These are durable project records only. They do not set, remove, or enable debugger runtime breakpoints. The current project schema has no breakpoint name field, so this ABI exposes address, kind, enabled state, size, and stable row ID; names are not persisted or returned.

C callers use the versioned table directly:

```c
const HexLabActiveProjectBreakpointApi *bp = NULL;
if (host->struct_size >= offsetof(HexLabHostApi, active_project_breakpoint_api) +
                             sizeof(host->active_project_breakpoint_api))
    bp = host->active_project_breakpoint_api;
if (bp && bp->struct_size >= offsetof(HexLabActiveProjectBreakpointApi, set) + sizeof(bp->set) &&
    bp->snapshot && bp->query && bp->set &&
    bp->api_version == HEXLAB_ACTIVE_PROJECT_BREAKPOINT_API_VERSION) {
    HexLabActiveProjectToken token = {0};
    token.struct_size = sizeof(token);
    token.document.struct_size = sizeof(token.document);
    if (bp->snapshot(bp->host_context, &token) == 0) {
        HexLabProjectBreakpointRecord rows[32] = {0};
        uint32_t written = 0;
        for (unsigned i = 0; i < 32; ++i) rows[i].struct_size = sizeof(rows[i]);
        bp->query(bp->host_context, &token, 0, 32, rows, &written);
        bp->set(bp->host_context, &token, address_space, address,
                HEXLAB_PROJECT_BREAKPOINT_SOFTWARE, 1, 1, 0);
    }
}
```

The C++ SDK provides table-prefix checks:

```cpp
hexlab::plugins::sdk::ActiveProjectBreakpointClient breakpoints(host);
HexLabActiveProjectToken token{};
if (breakpoints.snapshot(token) == 0) {
    HexLabProjectBreakpointRecord rows[32]{};
    for (auto& row : rows) row.struct_size = sizeof(row);
    uint32_t written = 0;
    breakpoints.query(token, 0, 32, rows, &written);
    breakpoints.set(token, address_space, address, HEXLAB_PROJECT_BREAKPOINT_SOFTWARE, 1);
}
```

Register it from `start` after checking that `host->struct_size` reaches
`register_analysis_provider` and that the function pointer is non-null. The
provider descriptor and callback state remain module-owned through `stop`; the
host copies descriptor strings and function/context pointers at registration.

The CLI accepts repeatable `--plugin <module>` options for `inspect` and
`disassemble`, and keeps the manager alive through detection, image loading,
analysis, and output. Automatic detection calls `detect_with_extensions` first;
claims for the existing `pe`, `elf`, and `macho` format IDs select those built-in
loaders. A plugin format without a registered image-construction service is
reported as unsupported. Callback errors are returned instead of hidden by
fallback.

For backward compatibility, `apply_display_extension` still permits legacy
ABI 1.3 processor extensions to change display text on a core-decoded NOP only.
It also replaces an opaque display row with a same-length validated semantic
instruction when a new callback claims the bytes. Both CLI and desktop use
this row-decoration path. `decode_with_extensions` returns semantic records
as core `Instruction` objects for IR consumers. `PluginManager::analysis_options`
also supplies the semantic decoder to function recovery and reachable
analysis. Accepted branch/call and absolute-memory effects therefore contribute
to project references and recovered functions, and are serialized in the
existing derived cache. Reopening requires the same active semantic extension
set. ABI 1.10 also supplies the image-construction service described below.

ABI 1.6 appends `decode_semantic` to `HexLabProcessorExtension`. The existing
descriptor prefix through `decode` is unchanged: hosts only read the new
callback when `struct_size` covers it, so ABI 1.3 descriptors remain valid.
This callback returns a bounded generic semantic record (up to four register,
immediate, relative, or absolute-memory operands, a known flow kind, and
read/write access for each operand). The host validates every enum, count, reserved field, string,
width, length, and access value before constructing an `Instruction` with
typed operands and register effects. Relative operands are accepted only for
control transfers; their targets use checked address arithmetic. Absolute
memory operands provide a resolved address and read/write effect. Invalid
records fail dispatch; a clean
decline continues to the next extension and then the built-in decoder. The
extension-aware `decode_with_extensions` returns this core instruction form,
which downstream IR consumers can use. Generic extension instructions use
`Opcode::opaque`, so opcode-specific lifting, stack modeling, and architecture
state effects are not inferred. Absolute-memory operands carry a single
resolved address; the ABI cannot represent base-plus-index memory addressing.
The ABI 1.3 record does not describe flags, implicit
effects, delay slots, or architecture-specific predicates. Callbacks receive
at most 32 input bytes and results have fixed capacities. As with other
in-process callbacks, execution time cannot be preempted; dispatch holds the
manager lock, so unload waits for a callback to return. Analysis cache identity
includes a manager generation as well as plugin/version/extension metadata. If
that identity changes during analysis, the worker rejects its result instead
of publishing a mixed decode. Plugin authors should still change their version
when semantic behavior changes.

The desktop Plugins panel keeps the same manager alive while a module is
loaded. The Disassembly page applies display extensions to a copy of each row's
instruction at render time. Loading or unloading a plugin rerenders the visible
page and refreshes loaded project analysis with the current semantic extension
set. Automatic image loading also probes registered image providers through the
shared loader path while that manager is alive, including desktop project
creation. Hosts can explicitly select one through `PluginManager::image_recipe`.

Desktop plugin actions run on the Plugins panel's serialized plugin worker,
alongside load and unload operations. This keeps slow native callbacks off the
UI event thread and prevents an action callback from racing a lifecycle change.
The panel reports the action result when the callback returns; the callback is
synchronous and cannot be forcibly interrupted by the host.

Project paths are limited to 32,767 UTF-8 bytes; a function page must contain 1–4,096 entries. Callback return `0` means success, `-1` means invalid arguments or incompatible data, and `-2` means the host operation failed. No C++ exception crosses the ABI. Projects are synchronous and thread-affine: create/open, analyze, query, and close a handle on the same thread. A plugin should close every handle before returning from `stop`. The host also releases remaining handles after `stop` and before unloading the module. Handles become invalid when closed or when the plugin unloads. C callers initialize `HexLabProjectSummary.struct_size` and every output record's `struct_size` before invoking callbacks. The C++ `ProjectClient` initializes `struct_size` for every record in a paged query's provided capacity before calling the host, so zero-initialized arrays can be passed directly. The host reports derived status using the `DerivedStatus` ordinal (fresh, pending, stale, incomplete, file-only); callers should treat unknown future values conservatively.

The C++ `hexlab::plugins::sdk::ProjectClient` wraps the table with move-only RAII ownership. It is header-only and keeps the C ABI unchanged. For example:

```cpp
hexlab::plugins::sdk::ProjectClient project(host);
if (project.available() &&
    project.create("sample.hxproj", "sample.elf", HEXLAB_PROJECT_FORMAT_AUTO) == 0 &&
    project.analyze() == 0) {
    HexLabProjectSummary summary{};
    if (project.summary(summary) == 0) {
        // summary.function_count and summary.instruction_count are available.
    }
}
```

The same wrapper exposes `import_header`, paged `types`, and `assign_type`; `supports_types()` checks that the complete ABI 1.13 tail is present. For example, after opening a writable project, call `import_header(source, nullptr, summary)`, pass a zero-initialized page of `HexLabTypeRecord` entries to `types(0, count, records, written)`, then pass a chosen record's ID and mapped address to `assign_type`. ABI 1.14 adds `declarations`, `enum_values`, and `supports_declarations()` for role-aware queries and exact enumerator values. Automatic record initialization applies to all paged `ProjectClient` queries; direct C callback callers keep the explicit initialization requirement.

`tests/plugins_sdk/example_plugin.c` exercises the C callbacks during module startup. `tests/plugins_sdk/sdk_tests.cpp` is a runnable native host example and contract test: it writes a tiny ELF executable, loads the module with the real platform loader, and verifies create/analyze/summary/function-page/close/open plus C++ RAII and page-bound checks. In the full build, run it through `ctest -R '^plugin_sdk$'`; to run manually, invoke `hexlab_sdk_tests <path-to-hexlab_sdk_example-module>`.

The SDK integration module also allocates extension callback state in `start`, passes it through each descriptor's opaque context, and releases it from `stop`. The host test dispatches both loader and processor callbacks while the module is loaded, then verifies registrations and dispatch results disappear after unload. A separately built ABI 1.0 module returns a `HexLabPluginApi` whose `struct_size` ends at `stop`; the same host test loads it and invokes its action to keep append-only descriptor compatibility covered.

The project service is an in-process trusted-plugin API, not a sandbox. The host does not impose filesystem authorization beyond path and format validation; load only plugins from sources the user trusts.

## Plugin image providers (ABI 1.10)

`HexLabLoaderExtension` keeps its original prefix through `probe` and appends
`image_api_version` and `load_image`. Old descriptors ending at `probe` remain
valid and retain their probe-only behavior. To supply images, set the version
to `HEXLAB_IMAGE_PROVIDER_API_VERSION` (1) and provide both callbacks. A null
image callback requires version zero. Registration rejects unsupported image
versions. Probe confidence does not establish that a provider can construct an
image; construction must succeed independently.

The image callback receives a borrowed `HexLabImageInput` and host-owned,
zero-initialized `HexLabImageMapping`. The host initializes the mapping's
`struct_size` and `api_version`; preserve them. Return zero only when the entire
mapping can be described accurately, or a negative status otherwise. Initialize
each used segment's `struct_size` to `sizeof(HexLabImageSegment)`. These V1
output records have fixed capacities and require their exact known sizes and
version. Reserved fields must be zero. Providers may not retain the input,
output, input context or read callbacks, and every read must finish before the
image callback returns. Exceptions are contained as callback failures.

Input reads copy original file bytes into plugin-owned buffers. Each request
must be nonempty, fit the input extent and be at most 1 MiB. An invocation is
limited to 4,096 reads and 64 MiB of cumulative requested bytes. A failed read
poisons the invocation even if the plugin subsequently returns success. The
host checks cancellation before and after the callback and during construction;
providers should also call `is_canceled` during long work. Native callback time
cannot be preempted, so providers must bound their own parsing and computation.
The host conservatively treats the entire original input as a mapping parser
dependency for project patch invalidation.

V1 describes one flat byte-addressed domain, 1–256 segments and 0–64 entry
addresses. Segment names are nonempty NUL-terminated strings in 64-byte buffers;
architecture and mode IDs use 32-byte buffers. Permissions contain only read
(1), write (2) and execute (4). Every nonempty memory range must fit the domain,
every backing extent must fit the original file, and file size cannot exceed
memory size. The tail beyond file size is zero-filled using normal `Image`
semantics. Overlapping virtual segments, arithmetic overflow and invalid
address widths are rejected by shared `Image::create`, as for built-in loaders.
Entries must be unique, mapped, executable and aligned for the selected mode;
executable segment beginnings must also satisfy that alignment.

Supported architecture/mode pairs and address widths are:

| Architecture ID | Mode ID | Width | Code alignment |
| --- | --- | ---: | ---: |
| `x86` | `x86_32` | 32 | 1 |
| `x86_64` | `x86_64` | 64 | 1 |
| `arm64` | `a64` | 64 | 4 |
| `riscv32` | `rv32` | 32 | 4 |
| `riscv64` | `rv64` / `rv64c` | 64 | 4 / 2 |
| `mips32` / `mips64` | `mips32` / `mips64` respectively | 32 / 64 | 4 |
| `powerpc` | `ppc32` / `ppc64` | 32 / 64 | 4 |
| `mos6502` | `m6502` | 16 | 1 |

Byte order is little (0), or big (1) for MIPS and PowerPC only. The provider
must decline formats needing transformed or decrypted storage, applied
relocations, multiple domains, ARM/Thumb mode profiles, segmented x86 state,
or another property that this mapping cannot express. The host rejects unknown
modes instead of substituting a flat approximation. V1 provides mapping data
only: it leaves `metadata_complete` false and emits a diagnostic rather than
claiming complete imports, symbols, relocations or other format metadata.

Host C++ code selects a provider with
`manager.image_recipe(plugin_id, extension_id)`. The result is a concrete
`LoadRecipe` usable with shared `load_image` and
`automation::Project::create(destination, input, recipe)`. It records exact
plugin ID, plugin version, extension ID, format ID and image API version.
Recipe codec version 6 stores bounded length-prefixed identities; earlier
recipe encodings are unchanged and remain readable. Recipe fingerprints
therefore include the provider identity. Providers must change their plugin
version when mapping behavior changes.

`Format::automatic` also probes active image providers before built-in format
detection, using at most 4,096 initial bytes and the real total input size. The
highest-confidence valid claim wins, with registration order breaking ties.
Only image-capable providers participate in this shared automatic path; older
probe-only extensions retain their existing runtime detection behavior. A
selected provider's construction failure is returned without trying another
format. A failed or malformed probe quarantines only that extension; if no
active image provider claims the input, built-in format detection continues.
Explicit built-in formats bypass plugin providers. Built-in-specific options
cannot be applied to a selected plugin image.

A live manager publishes each successful image provider through an RAII token
in the loader-owned registry. Duplicate exact identities are rejected. The
registry stores weak ownership and releases its lock before dispatch; dispatch
locks the manager against unload and verifies the complete identity again.
The existing project durable-load path uses this registry on reopen, with no
dependency from loaders back to plugins. Missing providers and version
mismatches produce an explicit loader error; existing project session policy
may expose the original bytes in `file_only` state with that error as its reason,
without an image or derived analysis. The host never loads executable module
paths from project data or falls back to another provider. Keep the manager alive through
creation, reopen, refresh and analysis, and load the same trusted module before
reopening. The resulting `Image` owns only validated host mappings and original
storage, so it remains safe to read after module unload.

Start and action callbacks can call synchronous host project services; the
manager permits that same-thread reentry while still serializing unload across
threads. Image provider dispatch reports busy when another thread owns the
manager, avoiding lock inversion across independent managers. Recursive plugin
image probing/loading from an image or probe callback
is rejected with a busy error. Use an explicit built-in loader when a provider
needs to inspect a separate built-in image through the project service.

## Enumerating plugin candidates

`PluginManager::scan_directory(path, max_entries)` provides a bounded, side-effect-free way for a host to populate a plugin picker. It inspects only direct children, ignores symlinks and nested directories (except a macOS `.bundle` directory), accepts the native module filename forms for the current platform, converts candidate paths to absolute UTF-8, and returns them in bytewise-sorted order. The default entry limit is 4,096; callers may choose a limit up to 16,384. Scans fail with a resource-limit error instead of returning an order-dependent partial list.

Each candidate may have an adjacent `<module filename>.hexlab-plugin` sidecar.
The version-1 data-only format lets a picker display declared identity and
capabilities before executing native code:

```text
format=hexlab-plugin-v1
id=org.example.xrefs
name=Cross-reference exporter
version=1.2.0
capability=analysis.provider,1,0,0
capability=project.read,1,2,0
requires=project.api,1,0
```

Blank lines and lines beginning with `#` are ignored. `id`, `name`, `version`,
and `format` must each occur once. `capability` may occur up to 256 times and
uses decimal major, minor, and flags fields. Optional `requires` lines may
occur up to 256 times and use `id,major,minimum_minor` for required host or
plugin-provided capabilities. The parser rejects unknown keys, duplicate IDs within either list,
malformed UTF-8 in names, control bytes, and files
larger than 64 KiB. `read_manifest(path)` exposes the same bounded parser for
package managers. Scan results leave `manifest` empty when there is no sidecar;
`manifest_error` records an invalid/unreadable sidecar without hiding the
module candidate. Neither scanning nor manifest parsing opens or queries the
module. When a manifest pins `sha256`, directory scanning records the
scan-time module digest or an integrity error. `PluginManager::load_candidate`
rechecks the pin before and after opening the module and checks declared
identity/capabilities before `start`; dependency activation applies the same
checks. A mismatch rejects candidate activation. Direct `load(path)` is an
explicit path load and has no sidecar snapshot to enforce. A manifest is not a
signature, does not identify a publisher, and does not sandbox native code.

Scanning does not open, query, or execute any candidate. It only identifies plausible module filenames; it cannot prove that a file exports the HexLab query symbol or has a compatible ABI. The host should show candidates to the user and call `PluginManager::load_candidate` only after selection. Loading a native module executes code in the host process (including platform loader initializers), so directory discovery is not a trust or sandbox boundary. Symlinked scan roots are rejected, and symlink entries are skipped.

The desktop Plugins view exposes this as **Scan Directory...**. Its separate “Discovered modules (not loaded)” list shows each candidate path, declared identity, version, and a bounded summary of declared capabilities; absent or invalid sidecar metadata is shown as a status. Scanning runs on the plugin operation worker without quiescing analysis or changing extension state. No candidate is preselected or loaded; the user must select a row and press **Load Selected Candidate**. That action then uses the normal serialized load and extension-quiescence path. The existing **Load Plugin** file/path action also remains an explicit load.

The candidate review pane shows the full path, sidecar identity, SHA-256 pin
and scan result, and each requirement's preflight resolution. **Load Selected
Candidate** calls `PluginManager::load_candidate`; any declared hash pin is
rechecked before and after module open, and loaded identity/capabilities are
checked before `start`. Direct path loading has no scanned sidecar pin.

For a selected candidate, identity and capability mismatches are rejected
before `start`. The operation status reports a match, mismatch, invalid or
unreadable sidecar, or no manifest. Direct path loading can still proceed
without a manifest snapshot; it does not establish module authenticity.

ABI 1.8 appends the optional `debugger_api` pointer to `HexLabHostApi`. Check
`HexLabHostApi.struct_size` through that field, then check the debugger table's
`struct_size` and `HEXLAB_DEBUGGER_API_VERSION` before using it. Older 1.x
modules remain compatible because the host only reads fields present in each
descriptor. The table creates native or GDB Remote Serial Protocol sessions;
it exposes process enumeration, launch/attach/connect, session state, detach
and interrupt, timed event wait and explicit continue/single-step
acknowledgement, thread/module/memory-region enumeration, memory and register
read/write, and breakpoint add/remove/enable/list.

All lists are paged at up to 4,096 records. Process enumeration is session
scoped. Memory reads and writes are capped at 1 MiB per call; event waits are
capped at 30 seconds; launch arguments are capped at 256. Fixed ABI strings
must fit their destination buffers, and register values larger than 64 bytes
are rejected rather than truncated. Initialize every output record's
`struct_size`; input records are similarly size checked. Callback status `0`
means success, `-1` means invalid arguments or handle, and `-2` means the
backend operation failed. A wait timeout is a backend failure status; callers
can query session state separately. Event sequence numbers must be passed back
to continue or single-step the matching stop. Event waits poll the backend in
50 ms slices, releasing the per-session operation lock between slices so
another thread can request an interrupt; the overall timeout is preserved.
Close marks the session unavailable and waits for the active slice to finish
before destroying its backend.

Debugger sessions belong to the host. Close each session before plugin `stop`
returns; as a final cleanup measure, the host closes leaked sessions after
`stop` and before unloading the module. Sessions are thread-affine. Calls are
synchronous, and a plugin must not unload while one of its own worker threads
is still using a session. The C++ SDK offers move-only RAII
`hexlab::plugins::sdk::DebuggerClient`; it checks the appended host field and
creates/closes a session while exposing the versioned table for operations.
`create()` initializes its output handle, closes a non-null handle returned on
failure, and rejects a host that reports success without returning a handle.
`processes(start, capacity, output, written)` pages the backend process list and
initializes each output record, up to the debugger page limit. It also wraps
launch/attach/remote-connect/state/detach, interrupt requests, event
continuation, bounded memory reads/writes, thread/module/memory-region pages,
breakpoint add/remove/enable/list, and paged register reads/writes. These
methods check callback availability in the runtime table and initialize the
records they pass. For example:

```cpp
#include <array>

void inspect(hexlab::plugins::sdk::DebuggerClient& debug,
            std::uint64_t process_id, std::uint64_t thread_id,
            std::uint64_t address) {
    HexLabDebugProcess process{};
    if (debug.attach(process_id, process) == 0) {
        std::uint32_t state = 0;
        std::uint8_t has_process = 0;
        debug.state(state, has_process, process);
        std::array<HexLabDebugThread, 32> threads{};
        std::uint32_t thread_count = 0;
        debug.threads(0, static_cast<std::uint32_t>(threads.size()), threads.data(), thread_count);
        std::array<HexLabDebugModule, 32> modules{};
        std::uint32_t module_count = 0;
        debug.modules(0, static_cast<std::uint32_t>(modules.size()), modules.data(), module_count);
        std::array<HexLabDebugMemoryRegion, 32> regions{};
        std::uint32_t region_count = 0;
        debug.memory_regions(0, static_cast<std::uint32_t>(regions.size()), regions.data(), region_count);
        std::array<HexLabDebugBreakpoint, 32> breakpoints{};
        std::uint32_t breakpoint_count = 0;
        debug.breakpoints(0, static_cast<std::uint32_t>(breakpoints.size()),
                          breakpoints.data(), breakpoint_count);
        std::array<std::uint8_t, 16> bytes{};
        debug.read_memory(address, static_cast<std::uint32_t>(bytes.size()), bytes.data());
        std::array<HexLabDebugRegister, 32> registers{};
        std::uint32_t written = 0;
        debug.read_registers(thread_id, 0, static_cast<std::uint32_t>(registers.size()),
                             registers.data(), written);
    }
}
```

`launch` accepts a `HexLabDebuggerTarget` and initializes a local copy's size
field before calling the host. `write_registers` initializes each input
record's size field; callers still supply the desired register values and byte
counts. `connect_remote`, `add_breakpoint`, and other output-record methods
initialize the returned process or breakpoint. The process inventory example
shows page ownership, while its event-text snippet shows the larger ABI 1.31
message record. The legacy 256-byte event callback remains available through
the raw table for modules that need to support older hosts.

Backend support depends on platform and target. The native backend is only
available where the host's native debugger implementation is supported;
remote sessions use GDB RSP and may not implement every inspection operation.
The ABI exposes generic events and fixed records; it does not expose backend
private handles, arbitrary OS exception structures, or plugin-defined
register schemas. Debugger services are in-process and trusted, like the rest
of the native plugin API.

The `desktop_sdk_plugin` GUI integration test loads the same compiled C module through the desktop Plugins panel, creates and analyzes a fixture project during module startup, displays its metadata and action, invokes the action, and verifies unload. Its missing-module case verifies failed loading returns a nonzero test result without leaving a modal dialog open.

ABI 1.2 appends optional paged instruction, outgoing-reference, and string callbacks to `HexLabProjectApi`. Check `struct_size` through the individual callback offset before using each extension; the C++ `ProjectClient` exposes `supports_instructions()`, `supports_references()`, and `supports_strings()`. Instruction text and string previews in the legacy records use fixed 256-byte buffers; records too large for those buffers fail the page rather than being silently truncated. ABI 1.30 adds a separate larger instruction-text record while preserving those legacy layouts. Reference targets distinguish mapped locations, external identities, and unresolved references. The native SDK integration fixture now includes a direct call and a string, and verifies each query through the C plugin module.

ABI 1.34 appends `outgoing_references_range` to `HexLabProjectApi` and declares
`project.references.range` v1.0. It pages references whose source address is
inside a nonempty half-open virtual range `[begin, begin + size)`. The request
rejects address overflow, requires current derived analysis, and accepts page
capacities from 1 through `HEXLAB_PROJECT_MAX_PAGE`. Returned `HexLabReference`
records retain mapped, file-offset, external, and unresolved targets. Callers
advance `start` by the number of written records and stop when a page is short.
The C++ `ProjectClient` exposes `supports_outgoing_references_range()` and the
corresponding wrapper. Older project-table prefixes remain unchanged.

The standalone Function CFG Report example queries the first byte of each
inspected block with this API, counts returned outgoing-reference rows, and
marks the report truncated when its 16-row per-block page fills. It does not
assume a block extent from its start address.

ABI 1.5 appends optional `rename`, `comment`, and `bookmark` callbacks to
`HexLabProjectApi`. Older hosts and plugins remain compatible through the
existing `struct_size` checks. C plugins can call these callbacks directly;
C++ plugins can use `ProjectClient::supports_edits()` and its `rename`,
`comment`, and `bookmark` wrappers. Address locations carry an address space
and offset; file locations use a file offset and require address space zero.
The host routes edits through the same project commands used by the desktop,
so they participate in normal validation and persistence. Names and bookmark
labels are limited to 512 UTF-8 bytes, comments to 1 MiB. Invalid arguments
return `-1`, host command failures return `-2`, and success returns `0`.

The SDK integration fixture now edits the sample project from its C module,
checks malformed locations and oversized names are rejected, and reopens the
project to verify the name, comment, and bookmark were persisted.

The append-only `annotation_batch` tail groups up to 4,096 rename, comment, and
bookmark edits into one atomic project command. Each entry has a fixed-size
record, tagged edit kind, address/file location, bookmark-removal flag, and a
borrowed UTF-8 value copied by the host before it returns. The caller supplies
the edit revision from `HexLabProjectSummary.edit_revision` and an undo group;
the host rejects stale revisions before applying any entries. A successful
batch creates one history step, so undo and redo act on the complete group.
`ProjectClient::supports_annotation_batch()` and
`ProjectClient::annotation_batch()` check and invoke this optional table tail.
Older summary records remain valid; the host writes the appended revision only
when the caller's `struct_size` includes it.

```cpp
HexLabProjectSummary summary{};
if (project.summary(summary) == 0) {
    HexLabProjectAnnotationEdit edits[2]{};
    for (auto& edit : edits) {
        edit.struct_size = sizeof(edit);
        edit.location.struct_size = sizeof(edit.location);
        edit.location.kind = HEXLAB_PROJECT_LOCATION_ADDRESS;
    }
    edits[0].kind = HEXLAB_PROJECT_EDIT_RENAME;
    edits[0].location.address_space = 0;
    edits[0].location.offset = 0x401000;
    edits[0].value = "entry_point";
    edits[1].kind = HEXLAB_PROJECT_EDIT_BOOKMARK;
    edits[1].location.address_space = 0;
    edits[1].location.offset = 0x401000;
    edits[1].value = "reviewed";
    project.annotation_batch(summary.edit_revision, 7, edits, 2);
}
```

ABI 1.11 appends an optional exact `read` callback to `HexLabProjectApi`. It
copies bytes from the project's effective image at either a mapped address or
a file offset, so plugins inspect the same patched image view as project
analysis. Requests must be nonempty and at most 1 MiB; an invalid location,
unmapped range, or read failure returns an error instead of partial data.
Older hosts and modules remain compatible through the existing `struct_size`
checks. C++ modules can check `ProjectClient::supports_read()` and call
`ProjectClient::read(location, size, output)`.

ABI 1.12 appends the optional `register_menu_action` callback to
`HexLabHostApi`. Check `struct_size` through that field before using it. A
menu action supplies a slash-separated path below the host's Extensions menu,
an action ID, a label, and the same opaque callback context used by ordinary
plugin actions. Paths have at most eight components and 256 bytes total; each
component is at most 64 bytes, and empty, dot, dot-dot, and control-character
components are rejected. Action IDs remain unique within the plugin, including
across panel and menu registrations.

The host copies the path and label during plugin start. While a load or unload
operation is pending, the Plugins panel rejects menu dispatch; after the
operation finishes, the Extensions menu is rebuilt from the manager's current
registrations. Dispatch looks up the current plugin and action IDs again, so
an event for an unloaded action cannot reach its module. Menu activation runs
through the Plugins panel's worker rather than the wxWidgets event thread. The
plugin manager serializes each invocation against stop and unload, keeping the
module loaded through an active callback. The C ABI does not expose wxWidgets
objects or permit plugins to retain host-owned menu pointers.

The SDK integration example registers `sample.inspect` for the Plugins panel
and, when the host table includes the ABI 1.12 tail, registers a second entry at
`Extensions > Analysis > Examples > Log sample action`. Invoking either entry
logs through the host callback. The example checks `struct_size` and the
optional function pointer before using the menu API, so it still loads on an
older ABI 1.x host and retains its panel action.

ABI 1.7 appends `decode_semantic_v2` to the processor descriptor and leaves the ABI 1.6 callback and record layout unchanged. A V2 callback returns up to four explicit operands, sixteen implicit register reads and writes, a generic condition value, and a delay-slot count. Operand kinds include registers, immediates, relative targets, absolute memory, and base-plus-index memory with scale and signed displacement. The host validates register-bank/mode matches, widths, counts, address arithmetic, and the full record before converting it to the same core `Instruction` representation used by analysis. Base and index registers are recorded as reads; explicit and implicit register effects are merged without duplicates. `HEXLAB_INSTRUCTION_FLOW_JUMP` is available for an unconditional direct or indirect jump. The generic condition is preserved as metadata; plugins and consumers must agree on its architecture-specific meaning. Delay slots are represented on the instruction, but the current analysis engine does not yet model their execution ordering. V2 callbacks are preferred over V1 when both are registered; a clean decline continues through the extension list and then the built-in decoder. Existing V1 modules remain compatible.

`examples/plugins/semantic-v2` is a standalone CMake module example. It registers an x86-64 processor extension and recognizes `8B 04 88` as a `mov` from `[rax+rcx*4]` into `eax`, demonstrating typed register and base-index memory operands. Configure it with CMake, build the module, then load that module using the CLI's `--plugin` option with a matching x86-64 disassembly request. The example deliberately declines all unrelated byte sequences.

ABI 1.16 appends optional `decode_semantic_v3` to `HexLabProcessorExtension`. The callback embeds an unchanged V2 semantic record and adds up to four per-operand base writeback records. A record describes pre-index writeback (`[base + displacement]!`) or post-index writeback (`[base], displacement`). The selected operand must be base-plus-index kind with a base. Pre-index accepts a decoded index register, scale, and extension as part of the same address expression; its memory displacement must equal the writeback displacement, and the host marks the base register written. Post-index requires zero effective memory displacement and no index because V3 has no separate post-index register field. The host persists writeback metadata in derived and reference caches and includes the notation in generic disassembly formatting. Malformed records and indexed post-index updates are rejected. V3 is preferred over V2 and V1 when present; existing descriptors and modules remain compatible through the append-only descriptor size check.

Semantic extensions use the same processor dispatch path in CLI and desktop analysis. Load them through the existing CLI `--plugin` option or desktop Plugins manager; no V3-specific setting is required.

## Active document context (ABI 1.15)

ABI 1.15 appends `active_document_api` to `HexLabHostApi`. Check the host `struct_size` through that pointer, then check the table's own `struct_size` and `HEXLAB_ACTIVE_DOCUMENT_API_VERSION`. Older ABI 1.x modules keep their existing host-table prefix. The desktop host provides `query`, `read`, and `navigate`; other hosts may expose the table but return an operation failure when no active desktop document is available.

`query` returns fixed-size metadata and a value-only `HexLabDocumentToken`. The token records active document ID, a nonzero monotonically assigned open generation independent of edit revisions, and current project edit/byte/decision revisions. It is not a handle and keeps no object alive. Every `read` and `navigate` call revalidates the token. A tab switch, reopen, or project revision change returns `HEXLAB_ACTIVE_DOCUMENT_STALE`; query again before retrying. Architecture and mode IDs are fixed NUL-terminated ASCII identifiers. No C++ or wxWidgets object crosses the ABI.

Reads accept address-space locations or file offsets and are exact, bounded to 1 MiB, and backed by the effective image/file view. The active document and token are checked before and after each bounded read so a tab switch during the read is reported stale. Invalid, unmapped, or stale reads leave the caller's output unchanged. Navigation accepts the same location records and uses normal document navigation history. Calls from a plugin worker are marshalled to the UI owner thread and wait at most five seconds; an expired or stale request is rejected. Calls made on the owner thread run directly. Tokens do not extend document lifetime. Host tables and service contexts expire
when the plugin stops. `ActiveDocumentClient` in `sdk.hpp` performs table-version checks and initializes the query output structure.

The service is available to menu/action callbacks as well as registered extensions, but it does not grant mutation, arbitrary-project, database-handle, or process-memory access. Use `project_api` for explicit project handles and its command-backed edits.

C++ modules can use the non-owning wrapper:

```cpp
hexlab::plugins::sdk::ActiveDocumentClient active(host);
HexLabActiveDocumentInfo document{};
if (active.query(document) == HEXLAB_ACTIVE_DOCUMENT_OK) {
    HexLabProjectLocation location{sizeof(location), HEXLAB_PROJECT_LOCATION_ADDRESS,
                                   document.address_space, 0, entry};
    std::uint8_t bytes[16]{};
    const auto read = active.read(document.token, location, sizeof(bytes), bytes);
    if (read == HEXLAB_ACTIVE_DOCUMENT_OK)
        active.navigate(document.token, location);
}
```

The host may return `HEXLAB_ACTIVE_DOCUMENT_STALE` if the active document or its project revisions changed between query and use.

The standalone [`active-document-cpp` example](../examples/plugins/active-document-cpp/README.md)
demonstrates an action that reads a bounded prefix from the active effective
file view and handles stale tokens.

## Active debugger session (ABI 1.17)

ABI 1.17 appends `active_debugger_api` to `HexLabHostApi`; older host-table prefixes are unchanged. `ActiveDebuggerClient` in `sdk.hpp` is a non-owning wrapper. Its `query` returns the desktop debugger state, optional process identity, and a value-only token combining a unique session ID, session/stop generations, and the active document token. A token becomes stale when the target resumes, a debugger session is replaced, or the active document changes or reopens. Query again after any stale response.

The table is read-only and exposes paged thread lists, paged register reads for a thread, and exact process-memory reads. These operations require a stopped target. Pages are capped at 4096 records and memory reads at 1 MiB; the debugger backend may impose tighter bounds. Output record arrays must be initialized with each element's `struct_size`. The host validates request sizes and callback output counts, catches exceptions, and reports `HEXLAB_ACTIVE_DEBUGGER_NOT_STOPPED`, `HEXLAB_ACTIVE_DEBUGGER_STALE`, or a generic failure as applicable. No session handle, write operation, breakpoint mutation, or guarantee of particular register availability crosses this API.

```cpp
hexlab::plugins::sdk::ActiveDebuggerClient debugger(host);
HexLabActiveDebuggerInfo snapshot{};
if (debugger.query(snapshot) == HEXLAB_ACTIVE_DEBUGGER_OK &&
    snapshot.state == HEXLAB_DEBUGGER_STATE_STOPPED) {
    HexLabDebugThread threads[64]{};
    for (auto& thread : threads) thread.struct_size = sizeof(thread);
    uint32_t written = 0;
    const auto status = debugger.threads(snapshot.token, 0, 64, threads, &written);
    // Use the same snapshot.token for later register and memory reads.
}
```

Calls are safe from plugin worker threads; debugger backend access is serialized with desktop inspection. The token is a snapshot guard, not a lock: resumption may occur immediately after an operation succeeds.

The standalone [`active-debugger-cpp` example](../examples/plugins/active-debugger-cpp/README.md)
demonstrates the complete read-only sequence: query a snapshot, page stopped
threads, read one thread's registers, locate a recognized PC register, and
read a bounded byte prefix at that PC. It reuses the same token for every
operation and reports stale or unavailable results without attempting a
write or resume.

## Breakpoint rules on owned debugger sessions (ABI 1.19)

ABI 1.19 appends optional rule callbacks to `HexLabDebuggerApi`, preserving the preceding table prefix and the existing `HexLabDebugBreakpoint` record layout. `DebuggerClient` exposes setters for ignore counts, conditions, and logpoint state/message, plus `breakpoint_rule` for querying runtime hit count and configured rule fields. Use `supports()` or check the table size before calling an appended callback when supporting older hosts. Conditions are limited to 256 UTF-8 bytes and log messages to 1024 bytes; the host rejects oversized or invalid text. Unsupported callback behavior is reported by the callback status instead of being silently accepted.

`HexLabDebugBreakpointRule` is an optional separate record with fixed-size condition and log-message fields, so existing list consumers remain layout-compatible. Runtime hit counts reset with the debugger session. The desktop persists rule configuration in project breakpoints; plugin-owned runtime session rules remain session-scoped. Core event messages are bounded to 4096 bytes. The legacy `HexLabDebugEvent.message` retains its 256-byte capacity and receives a marked UTF-8-safe prefix when longer output is shortened. See [the breakpoint workflow](debugger-breakpoint-workflow.md) for expression semantics and backend limits.

ABI 1.31 appends `wait_event_text` to `HexLabDebuggerApi` and declares the
`debugger.event-text` v1.31 capability. It returns the same event fields and
sequence number as `wait_event`, with `HexLabDebugEventText.message` holding up
to 4096 UTF-8 bytes plus a terminator. The prior `HexLabDebugEvent` record and
callback retain their exact ABI layout and bounded-prefix behavior. C++ callers
can check `DebuggerClient::supports_event_text()` and use
`wait_event_text(timeout_ms, event)`; the wrapper initializes the output
record. A returned event's sequence must still be passed to the matching
continue or single-step callback.

## Capability requirements (ABI 1.20)

ABI 1.20 appends the host's `declared_capabilities` table to `HexLabHostApi`
and `required_capabilities` to `HexLabPluginApi`. Both are bounded to 256
records. A plugin requirement matches only the same capability ID and major
version with a provided minor version at least as high as the requested minimum.
The host takes precedence; otherwise exactly one compatible loaded plugin can
satisfy a requirement. Legacy string capability labels do not satisfy versioned
requirements. Requirement flags must be zero. Invalid and duplicate requirements reject the
module; a valid but unavailable requirement makes `PluginManager::load` return
`unsupported` before calling the plugin's `start` callback. The module's native
loader initializers and `hexlab_plugin_query` have already executed by then,
so this is compatibility negotiation, not a sandbox or trust check.

The host currently declares `hexlab.host` v1.35; `project.api` v1.0,
`project.queries` v1.2, `project.edits` v1.6, `project.read` v1.11, and
`project.types` v1.14; `debugger.api` v1.8 and `debugger.rules` v1.19;
`loader.image` v1.10; `processor.semantic.v2` v1.7 and
`processor.semantic.v3` v1.16; `analysis.provider` v1.9; `document.active`
v1.15; `debugger.active` v1.17; `project.breakpoint.active` v1.18; and
`project.cfg` v1.21, `project.history` v1.28, and
`project.function-owners` v1.29, `project.instruction-text` v1.30,
`debugger.event-text` v1.31, `project.string-preview` v1.32, and
`plugin.state` v1.33, and `project.references.range` v1.0. These
versions describe table contracts; they do not promise that an active project,
document, or debug target exists at the moment a callback runs. Existing ABI
1.x modules with the old descriptor prefix remain loadable and have no declared
requirements.

## Plugin-owned state (ABI 1.33)

ABI 1.33 appends `plugin_state_api` to `HexLabHostApi` and declares the
versioned `plugin.state` v1.0 capability. `PluginStateClient` in `sdk.hpp`
checks the host-table tail, service-table size, and service version before use.
Older host prefixes are unchanged. The service stores opaque byte values under
the calling plugin's loaded plugin ID and retains them across unload/reload.
Desktop and plugin-enabled CLI managers persist them across process restarts in
the current user's state directory (`%LOCALAPPDATA%\HexLab` on Windows,
`$XDG_STATE_HOME/hexlab` on non-Windows systems when set, otherwise
`$HOME/.local/state/hexlab` on Linux or
`$HOME/Library/Application Support/HexLab` on macOS). The file is host-owned and is
separate from project files. Managers constructed with the legacy one-argument
constructor, including embedded/test managers, remain in-memory only; hosts can
opt in by passing a state file path to the two-argument constructor.

The v1 file is bounded to 80 MiB and uses a versioned binary representation
with a SHA-256 corruption check. A missing file starts with empty state. Invalid,
truncated, unsupported, oversized, or unreadable files cause state callbacks to
return `HEXLAB_PLUGIN_STATE_FAILED`; the host does not replace the bad file with
an empty store. A failed write also returns `FAILED` and rolls back that
operation in memory. Writes use a temporary sibling file and atomic replacement.
Persistence is local to one user profile and does not encrypt plugin data.
Concurrent managers or HexLab processes sharing the same state file are not
coordinated; the last atomic replacement may overwrite another writer's newer
state.

Keys are 1 to 128 ASCII characters from `[A-Za-z0-9._-]`. Values are arbitrary
bytes up to 64 KiB. Each key has a monotonically increasing revision; reads
return the current revision, and `set` or `erase` requires the caller's expected
revision. Use revision zero to create a new key. A stale write returns
`HEXLAB_PLUGIN_STATE_CONFLICT` with the current revision, so callers can reread
and reconcile instead of silently overwriting concurrent state. Erasure leaves
a revision tombstone, preventing an old writer from recreating a just-deleted
key using revision zero. Empty values are supported. Reads report the required
buffer size and current revision; if the provided buffer is too small, the
output bytes remain untouched and `HEXLAB_PLUGIN_STATE_BUFFER_TOO_SMALL` is
returned.

The host bounds each plugin to 1024 keys and 4 MiB of live values, and the
manager-wide store to 4096 plugin IDs and 64 MiB of live values. Those limits
include state left behind by unloaded plugins. Revisions and erase tombstones
are persisted too, so compare-and-set behavior continues after restart.

```cpp
hexlab::plugins::sdk::PluginStateClient state(host);
uint64_t revision = 0;
uint64_t next_revision = 0;
const uint8_t mode[] = {1};
if (state.available() &&
    state.set("view.mode", revision, mode, sizeof(mode), next_revision) ==
        HEXLAB_PLUGIN_STATE_OK) {
    // Keep next_revision and pass it to a later set or erase.
}
```

For a value read, first call `get(key, nullptr, 0, required, revision)`; a
nonempty value returns `BUFFER_TOO_SMALL` and its required size. Allocate that
many bytes and call again. If another writer changes the value between calls,
the second call reports its current size and revision; retry with the new size.

The sidecar's optional `requires=id,major,minimum_minor` records mirror the
module requirements for picker display and post-load identity comparison. The
sidecar remains advisory: only the module's validated in-memory descriptor is
used to decide whether loading may proceed. The explicit dependency activation
API verifies the scanned manifest before starting each newly loaded module; see
[dependency activation](plugin-dependency-activation.md) for planning, rollback,
consumer-first unload and refreshed candidate availability. These prerequisites
do not transfer callable services from a provider to a consumer.

## Project control-flow queries (ABI 1.21)

ABI 1.21 appends `function_blocks`, `block_instructions`, and
`block_successors` to `HexLabProjectApi`; earlier table prefixes remain valid.
Check `struct_size` through each callback before calling it. These bounded
queries expose recovered basic blocks and typed CFG edges to native plugins,
using the same project analysis snapshot as function and instruction queries.
They require fresh or incomplete derived analysis; call `analyze` after an edit
that invalidates those facts.

`function_blocks` takes a function entry address and returns pages of
`HexLabBasicBlock` records. It rejects an address whose function owner is
ambiguous. The record includes an opaque block ID, start address, instruction
and successor counts, and whether the block has a stop reason. Use the block
ID only while the same analyzed project generation remains current. It is not
a persistent identity and becomes invalid after reanalysis, project close, or
reopen.

`block_instructions` pages the instructions for one block using the ordinary
`HexLabInstruction` record. `block_successors` pages `HexLabBlockSuccessor`
records. Edge kinds have stable `HEXLAB_BLOCK_EDGE_*` values; an edge may have
a target address, a target block ID, both, or neither when resolution is
incomplete. Pages accept 1 through 4096 records, and callers initialize every
output record's `struct_size`.

The C++ `ProjectClient` wrapper checks the entire appended table tail through
`supports_control_flow()` and provides matching page methods:

```cpp
hexlab::plugins::sdk::ProjectClient project(host);
if (project.open(project_path, true) == 0 && project.analyze() == 0) {
    HexLabBasicBlock blocks[128]{};
    for (auto& block : blocks) block.struct_size = sizeof(block);
    uint32_t block_count = 0;
    if (project.function_blocks(address_space, function_entry, 0, 128,
                                blocks, block_count) == 0 && block_count != 0) {
        HexLabBlockSuccessor edges[32]{};
        for (auto& edge : edges) edge.struct_size = sizeof(edge);
        uint32_t edge_count = 0;
        project.block_successors(blocks[0].id, 0, 32, edges, edge_count);
    }
}
```

The standalone C++ [`function-cfg-report-cpp` example](../examples/plugins/function-cfg-report-cpp/README.md)
shows how to require `project.cfg` v1.21, open a project read-only, page
functions, blocks, instructions, and successor edges, and stop at explicit
resource limits while clearly marking the report as truncated.

## Pure scalar instruction IR (ABI 1.22-1.29)

`HexLabProcessorExtension` now has a size-gated, append-only `decode_ir` callback.
The `processor.ir.scalar` v1.29 host capability accepts bounded typed integer
DAGs with exact register effects and parallel outputs. ABI 1.23 adds exact
equality and signed/unsigned ordering predicates; ABI 1.24 adds logical and
arithmetic shifts, ABI 1.25 adds modulo-width rotates, ABI 1.26 allows exact
full-width x86 FLAGS inputs/outputs, and ABI 1.27 adds CLZ/CTZ/POPCOUNT,
without changing the record layout. ABI 1.28 adds same-width `BSWAP` byte reversal;
ABI 1.29 adds same-width modular integer `NEG`.
FLAG outputs must equal the complete
16/32/64-bit mode register, be declared in the semantic effects, and be
computed as a same-width output formula; partial or non-x86 status writes
remain unsupported. Existing modules
requiring v1.22 remain compatible and can use the original operation set; a
module requiring newer operations is rejected by a host that only implements
an earlier capability minor. Hosts opt into common-IR lifting through
`plugins::lift_function_with_extensions`; snapshot fingerprints
and semantic generations are validated before formulas reach SSA/pseudocode.
Scalar IR currently has no memory-value operations. Although semantic V3 can
describe indexed pre-index writeback for ordinary decoded instructions, a
scalar-IR callback must still decline such instructions; adding it there needs
a versioned memory-IR representation so loads/stores and updated bases remain
one coherent effect.
Older processor descriptors and core lift overloads remain supported. See
[plugin scalar instruction IR](plugin-scalar-ir.md) for the precise record,
register, lifecycle and resource limits and the C-only custom-opcode example.
