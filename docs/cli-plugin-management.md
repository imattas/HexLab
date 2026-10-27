# CLI plugin discovery

`hexlab_cli plugins scan <directory>` enumerates direct native-module candidates and reads each adjacent `.hexlab-plugin` sidecar. It does not open a candidate module, call its entry point, or execute plugin code. This lets build and deployment scripts inspect an installation directory without loading its contents.

The text output reports the module path, declared identity and version, capability declarations, and required capabilities. Candidates with no sidecar remain visible; malformed or unreadable sidecars are reported on their module candidate instead of hiding it. Discovery is bounded to 4,096 direct entries and uses the same platform module suffix and `.bundle` handling as the desktop plugin picker.

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
considered resolved for this check, but is still only an advisory manifest
match. Without `--strict`, both commands retain their ordinary successful
status for reportable metadata problems.

```text
hexlab_cli plugins scan ./plugin-root --strict
hexlab_cli plugins dependencies ./plugin-root --json --strict
```

The JSON object includes the scanned directory, a `loaded: false` marker, candidate count, and a `candidates` array. Each candidate has a path, a nullable manifest object, and a `manifest_error` string. Capability records contain their ID, major/minor version, and flags. JSON strings are escaped before writing. The command only reports advisory sidecar metadata; the host validates its identity against the loaded module during explicit load.

To load a plugin for a supported CLI operation, continue to pass its module explicitly with `--plugin <module>` to `inspect`, `disassemble`, or `decompile`. Scanning never changes files or plugin state.
