# Project recovery CLI

Inspect an orphan or suspect SQLite WAL without opening its source through
SQLite:

```powershell
hexlab_cli project recovery inspect-wal .\projects\sample.hxproj-wal --json
```

`inspect-wal` reads an existing regular file directly. It does not open a
database connection, create WAL/SHM/journal companions, checkpoint, reconstruct,
rename, delete, or publish a project. It also works when the original database
is missing. Symlinks are rejected. The report is diagnostic only: checksum-valid
frames and commit markers do not establish that a WAL belongs to any particular
base database, contains a complete database, or can recover a HexLab project.

The inspector validates the exact SQLite WAL magic, format version 3007000,
power-of-two page size from 512 through 65536, header checksum, frame page
fields, matching header/frame salts, and cumulative checksums in the byte order
selected by the magic. It stops at the first invalid frame; mismatched salts
may represent a stale suffix left by a legitimate WAL reset. The report keeps
the checksum-valid frame count separate from validated commit markers, the
last such marker's frame/database-page count, valid frames after that marker,
and incomplete trailing bytes. These follow the
[SQLite WAL format](https://sqlite.org/fileformat2.html#walformat).

Scanning defaults to 4096 frames and 64 MiB of reads, including a final header
recheck. `--max-frames` accepts 1..65536 and `--max-bytes` accepts 64..67108864.
The API exposes the same limits through `database::inspect_wal`; cancellation
returns an error instead of a partial report. Memory use is bounded to one
page/frame buffer plus fixed headers. Budget exhaustion returns the validated
prefix with `frame_limit` or `byte_limit`, rather than treating unexamined
frames as valid. JSON uses schema 1, `operation: "inspect-wal"`, and
`diagnostic_only: true`; `header_valid`, `scan_complete`, and `stop_reason`
describe the result. Exit 0 means every complete frame was validated and no
partial frame remained. Exit 3 means the file was empty, invalid, truncated,
or the scan reached a budget; neither exit code claims database recovery.

Size, modification time, and header checks reject obvious concurrent changes.
They do not provide a SQLite transaction snapshot or prove stability against
an active writer; use an offline copy for diagnosis. Base-database association,
WAL replay, page salvage, and repaired-project publication remain unsupported.

List recovery artifacts in a directory without changing any files:

```powershell
hexlab_cli project recovery list .\projects --json
```

Add `--inspect-wal` to include bounded diagnostics for matching project
(`*.hxproj-wal`) and HexLab staging (`.hexlab-save-*.tmp-wal` or
`.hexlab-previous-*.tmp-wal`) WAL sidecars:

```powershell
hexlab_cli project recovery list .\projects --inspect-wal --json
```

The option reads at most 8 matching WAL files, 8 MiB and 1,024 frames per
file, across at most 8,192 directory entries. JSON adds a `wal_diagnostics`
object with each inspected header/frame/commit summary, bounded per-file
errors, and omission/completeness counts; text output prints the same summary.
The CLI does not associate any WAL with a database, replay frames, or offer a
WAL as a recovery candidate. These diagnostics do not change candidate
validation or restore behavior. A WAL that is invalid, truncated, or budget
limited makes the optional diagnostics incomplete and returns exit code 3.

Use `--kind interrupted-save` or `--kind previous-version` to show only one
artifact class. The scan still validates all matching recovery-name candidates
before filtering, so the filter does not weaken validation or bypass directory
scan limits:

```powershell
hexlab_cli project recovery list .\projects --kind previous-version --json
```

Filtered JSON reports `scanned_candidates` (the validated total before the
filter) and `kind_filter` (`interrupted_save`, `previous_version`, or `null`)
alongside the filtered `candidates` array. Text output reports the filtered
count and total.

After a project fails to open, pass that project path to scan beside it without
having to extract its directory first:

```powershell
hexlab_cli project recovery list .\projects\sample.hxproj --json
```

The report identifies the scanned directory and, when given a project path,
echoes that path as `project_path`. Discovery only reports validated sibling
artifacts; it does not alter the project or select an artifact to restore.

The scan considers only files with HexLab's interrupted-save or
retained-previous-version names. Each candidate is opened through the normal
read-only project validation path, including schema, project rows, patch ranges,
embedded input checks, and a complete forward/inverse audit of retained edit
history. History verification shares a scan-wide budget of 65,536 history steps
and 512 MiB of history payload. A candidate whose history does not fit the
remaining budget is rejected with a bounded reason; later candidates are also
rejected after either history budget is exhausted. Exact-file identity hashing
uses a separate 1 GiB scan-wide budget and reads each candidate before and
after database validation. Directory scans are bounded to 8,192
entries and 256 candidate names. JSON includes `visited_entries`,
`matching_names`, `scan_complete`, `omitted_candidates`, `rejected_candidates`,
and up to 64 `rejections` with filename and bounded reason, plus
`omitted_diagnostics` when more failures occurred. Text output
prints the same rejection summary and examples. Non-regular files, unreadable
files, and artifacts that fail project validation are now visible in this
report instead of disappearing from the candidate count. JSON output reports
the UTF-8 path, project UUID, artifact kind, and the edit/byte/decision revision
triple captured at discovery for each validated candidate. Text output includes
the same triple as `revisions=edit:bytes:decisions`; it is a comparison aid, not
a timestamp or a substitute for restore-time validation.
Both text and JSON output also include `artifact_size` and `artifact_sha256`,
the exact candidate file identity pinned by discovery. Restore rechecks these
values before and during validation, so they can help diagnose why a delayed
restore conflicts when the artifact has changed. Discovery pins each
candidate's exact file size and SHA-256 using a cumulative 1 GiB hash-read
budget per directory scan. Candidates beyond
that budget are reported as rejected rather than offered for a delayed restore.
When the entry or candidate-name cap is reached, the detailed inspection API
returns the validated prefix with `scan_complete: false`; `omitted_candidates`
counts matching names that were seen but not validated after the candidate cap.
The CLI returns exit code 3 for this partial scan, and its text output reports
that a scan limit was reached. The simpler `discover_recovery_candidates()` API
returns a resource-limit error for incomplete scans so restore callers cannot
mistake a prefix for the full candidate set.

Restore one listed artifact to an independent project:

```powershell
hexlab_cli project recovery restore .\projects\.hexlab-save-abc.tmp --output .\recovered.hxproj
```

Add `--json` to emit a schema-versioned success object containing `restored`,
the published project `path` and fresh `uuid`, the `source_artifact` path, and
`source_retained: true`. The success object is emitted only after publication
succeeds; failures remain CLI errors and do not produce a success object.

Restore re-discovers and validates the artifact in its containing directory,
then the database API checks its kind and UUID again before copying it through
the checked Save As path. Recovery candidates pin the edit, byte, and decision
revisions plus exact staged-file size and SHA-256 seen during discovery; these
checks run on both sides of opening the candidate. If a caller delays
restoration and the artifact changes in the meantime, restore returns a
conflict instead of copying a different project state, even if the replacement
retains the same UUID and revisions. The new project receives a fresh UUID. The
artifact is retained unchanged. Existing output files are refused unless `--replace` is
explicitly supplied; output paths that alias protected source or project files
are rejected by the database publication layer.

Recovery discovery is not a general damaged-database repair tool. It lists
only complete HexLab staging artifacts that pass ordinary project validation;
corrupt or partial files are not modified or offered for restore. See
[Project format and recovery guarantees](project-format.md).

When opening a project fails in the desktop, its recovery scan also includes a
bounded summary of examined directory entries and rejected staging candidates
in the existing failure dialog. Up to eight filename/reason examples are
shown; additional diagnostic examples are counted as omitted. The scan remains
read-only, and only the validated candidates can be selected for opening.
Each choice includes the artifact kind, pinned edit/byte/decision revisions,
and exact staged-file size so the user can distinguish validated project
snapshots before opening one. The revision values are identifiers, not dates;
the selected artifact is still revalidated by the normal open path.

Restore a retained previous version over its existing project path when the
current project must be rolled back in place:

```powershell
hexlab_cli project recovery restore-in-place .\projects\.hexlab-previous-abc.tmp --target .\projects\sample.hxproj --json
```

This operation accepts only a validated `previous-version` candidate. The
database layer rechecks the candidate UUID, discovered revisions, exact file
size, and SHA-256, and requires the candidate and target to represent the same
project identity. It
uses the checked in-place publication path, so the target keeps its UUID and
the source recovery artifact remains available. It does not accept
`interrupted-save` candidates. Close all connections to the target before
running the command, then reopen the target afterward so applications reload
the restored database state. JSON success output is emitted only after the
restore completes and reports `target_uuid_preserved: true`.

The desktop File menu exposes this operation as **Restore Previous Version In
Place...**. Choose a retained `.hexlab-previous-*.tmp` artifact and its existing
project target. Recovery discovery and candidate validation run on a worker,
then the selected candidate is revalidated at publication. Only a
`previous-version` artifact is accepted. Close all open views of the target
before starting; the target is reopened after a successful restore, and the
recovery artifact remains available.
