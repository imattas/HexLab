# Function signature catalog extraction

`hexlab_cli project signature-catalog-create <project.hxproj> --all-functions --provenance <source>`
extracts one reusable byte-signature definition for every recovered function and
writes the canonical catalog text to stdout. Redirect stdout to save the result:

```text
hexlab_cli project signature-catalog-create target.hxproj --all-functions --provenance "internal build 42" > target.sigcat
```

The output is the version 2 signature catalog format consumed by `project
signatures` and `project signature-apply`. Its header binds the catalog to the
image architecture and execution mode. Each subsequent line has the existing
four-field signature schema:

```text
name|provenance|positive-pattern|excluded-pattern[;...]
```

Generated names are stable `sub_<space>_<entry>` labels. Relative branch/call
and statically addressed memory displacement bytes are wildcarded where the
decoder provides their encoding metadata. Extraction preserves recovered
function order and emits no catalog unless every selected function can be
signed.

The selection must contain 1 through 4,096 functions and recovery must be
complete. `--max-bytes N` sets the maximum pattern length (default 128,
permitted 1..256); `--min-exact-bytes N` sets the minimum exact-byte count
(default 8, permitted 1..`--max-bytes`). Provenance is required and must be
1..256 bytes without `|`, CR, or LF. The serialized catalog is capped at 1 MiB.
