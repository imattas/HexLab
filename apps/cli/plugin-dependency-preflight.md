# CLI plugin dependency preflight

`hexlab_cli plugins dependencies <directory>` scans the direct native module
candidates and their bounded `.hexlab-plugin` sidecars without loading or
executing any module. It reports each declared requirement as:

- `host` when the running HexLab host declares a compatible capability;
- `candidate` when exactly one other scanned manifest declares a compatible
  capability;
- `ambiguous` when multiple other candidate manifests could provide it; or
- `unavailable` when no host or candidate manifest provides it.

Use `--json` for machine-readable output. Candidate provider records include
both manifest ID and path. Candidates with no readable manifest retain an
unknown requirement state and include the scan diagnostic.

This is advisory metadata only. Sidecars are not authenticated, and candidate
modules are not queried to confirm that their native descriptors match the
sidecars. A later explicit load still validates the native descriptor and
required capabilities against plugins that are actually loaded. Directory
scanning never loads code.

With `--strict`, the command still emits the complete report but exits with
status 3 if a candidate has no readable manifest or any requirement is
unavailable or ambiguous. A unique candidate provider counts as resolved for
this status check; it is not proof that the module will load or satisfy the
ABI.
