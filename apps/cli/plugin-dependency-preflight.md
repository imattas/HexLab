# CLI plugin dependency preflight

`hexlab_cli plugins dependencies <directory>` scans the direct native module
candidates and their bounded `.hexlab-plugin` sidecars without loading or
executing any module. It reports each declared requirement as:

- `host` when the running HexLab host declares a compatible capability;
- `candidate` when exactly one other scanned manifest declares a compatible
  capability; the report also shows whether that provider's own manifest
  dependency graph is complete;
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
unavailable or ambiguous, if a candidate provider's transitive requirements
are unresolved, if the graph contains a cycle, or if the bounded graph walk
reaches its depth limit. The report includes a per-candidate
`dependency_status` (`ready`, `manifest_unavailable`, `unavailable`, `ambiguous`,
`cycle`, or `depth_limit`) and each unique candidate requirement's
`provider_dependency_status`. A ready graph means only that the supplied
manifest declarations are internally resolvable; it is not proof that a
module will load, match its declared ABI, or be safe to execute.
