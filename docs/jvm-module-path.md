# JVM module-path workspace linking

`link_jvm_path_workspace` inventories caller-supplied filesystem roots and
feeds their class and module metadata through `link_jvm_metadata_workspace`.
Roots are passed in caller order. A directory is traversed recursively without
following symlinks; regular files are sorted by generic relative path before
processing. A regular file root is read as one bounded ZIP/JAR archive.

Every module-path root must contain a root `module-info.class` with a valid
`Module` attribute. A descriptor-less module-path root is returned with
`missing_module_descriptor`; its classes have unresolved ownership. The
resolver does not derive automatic-module names from archive names or manifests.
Class-path roots contribute to one explicit synthetic unnamed classpath module.
Their class packages are resolved from root provenance. `META-INF/services`
files in classpath roots are parsed as line-oriented service-name text with
comments and whitespace; binary names are translated to the internal slash form
used by class metadata. The resulting provider references are linked against
the discovered classes.

## API example

```cpp
const std::array roots{
    JvmPathRoot{std::filesystem::path("app-modules"), JvmPathRootKind::module_path},
    JvmPathRoot{std::filesystem::path("lib/dependency.jar"), JvmPathRootKind::module_path},
    JvmPathRoot{std::filesystem::path("classes"), JvmPathRootKind::class_path},
};
auto workspace = link_jvm_path_workspace(roots, stop_token);
```

Roots are retained in the supplied order. Files within each directory are
visited by sorted generic relative path. Module records retain descriptor scan
order; duplicate names are marked by the workspace linker, with no first-wins
or last-wins selection. The synthetic unnamed classpath module gets the first
deterministic `hexlab.unnamed.classpath[.N]` name that does not collide with a
descriptor name. `workspace.roots` reports per-root module name/status and
file/class counts; `workspace.unnamed_classpath_module` is its graph index when
classpath roots were supplied.

The workspace also cross-checks `NestHost` and `NestMembers` attributes across
the class files already supplied by those roots. Each attribute reference is
retained as a relation with source and target metadata indexes when available,
the attribute's file offset, and one of `resolved`, `missing`, `ambiguous`,
`not_reciprocal`, or `cross_package`. A member-to-host reference resolves only
when the unique host lists that member exactly once; a host-to-member reference
resolves only when the unique member points back to that host. Duplicate class
definitions and duplicate membership entries remain ambiguous. Nestmates must
share the same internal package name. The CLI prints up to 256 relation rows.
This pass uses only the class metadata in supplied roots: it does not search
for missing classes or establish JVM defining-loader identity. Retained output
is capped at 100,000 references and 16 MiB. Linking also caps total reference
and reciprocal-membership visits at 100,000, polling cancellation during long
membership scans.

For class-path JAR roots, the main manifest's `Class-Path` attribute contributes
ordered relative file references. The workspace resolves a reference only when
the normalized target is also present among the caller-supplied class-path
roots. It never opens a path discovered only in an archive. Each JAR is placed
in `class_path_search_order` before its manifest entries; entries expand
depth-first in manifest order, followed by the next explicit class-path root.
A root is listed once. Cyclic back-edges are retained with `cycle` status;
references can also report `not_supplied`, `ambiguous`, `malformed_uri`, or
`unsupported_uri`. Absolute URLs, schemes, query/fragment components, escaped
path separators, and backslash paths are outside this local-file profile.
Percent-escaped bytes other than separators are decoded before matching.
Windows path matching folds ASCII case. This produces class-path precedence
metadata; it does not load a requested class or enforce package sealing or
other class-loader security rules. Manifest expansion is capped at 4,096
references and 4 MiB of URI text by default, in addition to the root, file, and
manifest limits.

`resolve_jvm_class_path_class(workspace, "pkg.Type")` performs a bounded
resource lookup using that effective order. It converts the binary name to
`pkg/Type.class`, chooses the first matching directory/JAR definition, and
returns later matches as shadowed rows. Within a root, directory paths use the
sorted traversal order and archive duplicates use archive member order. A
selected class whose declared internal name disagrees with its resource path
returns `class_name_mismatch` and remains the selected entry; lookup does not
fall through to a later root after that class-loading error. Results identify
the source root/resource, archive offset where applicable, shadowed definition
indices, and the owning unnamed classpath module. Lookup accepts Java binary
names, not descriptors or internal slash names.

The CLI exposes the resolver as:

```text
hexlab_cli jvm module-path --module-path app-modules --module-path lib/dependency.jar --class-path classes
hexlab_cli jvm module-path --class-path app.jar --class-path lib/dependency.jar --lookup-class com.example.Main
```

Repeat either option; roots are consumed in the exact option order. The command
prints graph totals and bounded samples: 256 roots, modules, and edges; 128
class-ownership and package rows; 256 service rows; and 64 cycle rows. Package
owners are shown by module name, up to eight names per package. Omitted row
counts are printed. It also shows up to 256 class-path search-order roots and
manifest references. Repeat `--lookup-class` for up to 64 bounded queries; each
prints the selected root/resource, classpath module owner, and up to 16
shadowed definitions. JAR volume sets use the existing separate `jar` command.

The defaults bound a workspace to 256 roots, 100,000 enumerated files/member
rows, 50,000 classes, 128 MiB per file/archive, 2 GiB aggregate filesystem
input bytes, 512 MiB aggregate class bytes, 16 MiB service text, and 65,536
non-empty service provider rows. ZIP parsing also uses `JarLimits`: at most
100,000 members, 128 MiB per member, and 4 GiB aggregate uncompressed bytes per
archive. All limits are caller-adjustable through `JvmModulePathLimits`.
Cancellation is observed during enumeration, class loading, archive member
processing, and service parsing.

Pass `--release <feature>` (or set `JvmModulePathLimits::target_release`) to
select multi-release JAR class overlays. This option applies only to regular
JAR roots whose main manifest has `Multi-Release: true`; the manifest attribute
name/value comparison is ASCII case-insensitive. The manifest is capped at 1
MiB by default, must have valid bounded main-header lines (72 bytes per
physical line, CRLF or LF, valid continuations), and duplicate or malformed
`Multi-Release` attributes are rejected. A missing manifest or a false value
leaves versioned entries ignored as before. With a valid multi-release
manifest, the workspace chooses the highest version directory from 9 through
the requested release for each logical `.class` path, including
`module-info.class`. Selected rows keep both logical and physical archive paths,
release number, archive data offset, and uncompressed size; the CLI shows a
bounded sample. Duplicate base class paths or duplicate logical class paths at
the same version are rejected as ambiguous. Distinct releases for one logical
path are valid. Physical archive member/file and ZIP expanded-size limits
still cover every entry, while class-count and aggregate class-byte limits
apply to the selected class set. Retained provenance paths have a shared 16 MiB
default cap. The resolver selects class metadata only; it does not overlay
resources or implement full runtime class-loader delegation. Retained class
lookup provenance shares the 16 MiB path budget; each query scans at most the
50,000 retained class definitions.

`resolve_jvm_module_configuration` computes a caller-rooted closure from the
already linked module graph. Exact unique root names are queued in caller order;
resolved `requires` edges are traversed breadth-first in descriptor order.
Missing or duplicate roots and unresolved required edges remain explicit and
make the result incomplete. Missing `requires static` edges are listed as
omitted optional edges and do not prevent completeness. Cycles terminate
through the visited-module set. The API is bounded to 256 roots, 4,096 resolved
modules, and one million module-lookup/edge visits, and supports cancellation.
Root lookup work is charged to the same budget and polls cancellation. The CLI
accepts repeated `--root-module <name>` options and prints the resulting
closure and unresolved edge indexes. It uses only descriptors already found
in caller-supplied module-path roots.

This is bounded metadata linking, not a Java runtime module resolver. It
reports duplicate module and class definitions, split packages, missing module
references, service-class ownership, and `requires` cycles using the existing
workspace linker. The optional rooted closure makes no choice among duplicate
definitions. It does not infer automatic modules, resolve the full JPMS
configuration graph, or enforce readability, exports,
opens, access control, loader delegation, or runtime permissions. The emitted
class-path order does not establish that service providers
implement the declared service interface or have valid constructors.
