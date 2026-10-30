# CLI plugin discovery

`hexlab_cli plugins scan <directory>` enumerates direct native-module candidates and reads each adjacent `.hexlab-plugin` sidecar. It does not open a candidate module, call its entry point, or execute plugin code. This lets build and deployment scripts inspect an installation directory without loading its contents.

The scan also groups readable manifests by their exact plugin ID and reports
identities declared by multiple candidate paths. This catches deployment
collisions even when the duplicates do not provide the same capabilities.
`scan --strict` returns status 3 for duplicate identities as well as malformed
or unreadable manifests and integrity failures. The JSON object includes a
`duplicate_identity_count` and a `duplicate_identities` array containing each
duplicate ID and its candidate paths. The `dependencies` report includes the
same array, and strict dependency checks fail on duplicate identities even if
all individual capability requirements resolve.

The text output reports the module path, declared identity and version, capability declarations, and required capabilities. Candidates with no sidecar remain visible; malformed or unreadable sidecars are reported on their module candidate instead of hiding it. A sidecar is read only when its adjacent path is a regular, non-symlink file. Symlinks and non-regular sidecars are rejected before parsing, remain visible as candidates with a manifest error, and are counted as invalid metadata by strict scans. The scan rechecks the path in the bounded manifest reader before opening it. Discovery is bounded to 4,096 direct entries and uses the same platform module suffix and `.bundle` handling as the desktop plugin picker.

An optional `sha256=<64 lowercase hexadecimal characters>` field pins the
adjacent native module's bytes. For example:

```text
format=hexlab-plugin-v1
id=sample.plugin
name=Sample Plugin
version=1.0
sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

When present, `scan` streams and hashes a regular module file without loading
it. Text output shows the declared and observed digest; JSON reports `sha256`,
`module_sha256`, and `integrity_error`. A mismatch or inability to hash is an
integrity failure, and `scan --strict` returns status 3 for it. Hashing is
limited to 1 GiB per module. A `.bundle` directory cannot be pinned with this
single-file field and will report an integrity error if a digest is declared.
This check catches byte mismatches but does not authenticate who produced the
module; a party able to replace both module and sidecar can replace the digest
too. Manifests without `sha256` remain unverified and are not hashed.

Use `--json` for machine-readable output:

```text
hexlab_cli plugins scan ./plugin-root --json
```

Append `--strict` to either `scan` or `dependencies` to make advisory metadata
problems affect the process status while still printing the full report. Strict
`scan` returns status 3 when one or more sidecars are malformed or unreadable;
modules without a sidecar remain valid candidates. Strict `dependencies`
returns status 3 when a candidate has no readable manifest or when any required
capability is unavailable or ambiguous. A unique candidate provider is
considered directly matched, then its transitive requirements are checked from
the same scanned manifests. Cycles, unresolved provider requirements, and
dependency walks deeper than the bounded limit also produce status 3. A
`ready` manifest graph is still only advisory: it does not authenticate a
module or confirm its native ABI. Without `--strict`, both commands retain
their ordinary successful status for reportable metadata problems.

```text
hexlab_cli plugins scan ./plugin-root --strict
hexlab_cli plugins dependencies ./plugin-root --json --strict
```

The JSON object includes the scanned directory, a `loaded: false` marker, candidate count, and a `candidates` array. Each candidate has a path, a nullable manifest object, and a `manifest_error` string. Capability records contain their ID, major/minor version, and flags. The `dependencies` report also includes each candidate's transitive `dependency_status` and a `provider_dependency_status` for each unique candidate provider. JSON strings are escaped before writing. The command only reports advisory sidecar metadata; the host validates its identity against the loaded module during explicit load.

To load a plugin for a supported CLI operation, continue to pass its module explicitly with `--plugin <module>` to `inspect`, `disassemble`, or `decompile`. Scanning never changes files or plugin state.
