# Project recovery CLI

List recovery artifacts in a directory without changing any files:

```powershell
hexlab_cli project recovery list .\projects --json
```

After a project fails to open, pass that project path to scan beside it without
having to extract its directory first:

```powershell
hexlab_cli project recovery list .\projects\sample.hxproj --json
```

The report identifies the scanned directory and, when given a project path,
echoes that path as `project_path`. Discovery only reports validated sibling
artifacts; it does not alter the project or select an artifact to restore.

The scan considers only regular files with HexLab's interrupted-save or
retained-previous-version names. Each candidate is opened through the normal
read-only project validation path, including schema, project rows, patch ranges,
and embedded input checks. Unopenable artifacts are skipped. Directory scans
are bounded to 8,192 entries and 256 validated candidates. JSON output reports
the UTF-8 path, project UUID, artifact kind, and the edit/byte/decision revision
triple captured at discovery for each candidate. Text output includes the same
triple as `revisions=edit:bytes:decisions`; it is a comparison aid, not a
timestamp or a substitute for restore-time validation.

Restore one listed artifact to an independent project:

```powershell
hexlab_cli project recovery restore .\projects\.hexlab-save-abc.tmp --output .\recovered.hxproj
```

Restore re-discovers and validates the artifact in its containing directory,
then the database API checks its kind and UUID again before copying it through
the checked Save As path. Recovery candidates also pin the edit, byte, and
decision revisions seen during discovery; if a caller delays restoration and
the candidate changes in the meantime, restore returns a conflict instead of
copying a different project state. The new project receives a fresh UUID. The
artifact is retained unchanged. Existing output files are refused unless `--replace` is
explicitly supplied; output paths that alias protected source or project files
are rejected by the database publication layer.

Recovery discovery is not a general damaged-database repair tool. It lists
only complete HexLab staging artifacts that pass ordinary project validation;
corrupt or partial files are not modified or offered for restore. See
[Project format and recovery guarantees](project-format.md).
