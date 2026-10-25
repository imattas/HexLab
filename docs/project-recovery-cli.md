# Project recovery CLI

List recovery artifacts in a directory without changing any files:

```powershell
hexlab_cli project recovery list .\projects --json
```

The scan considers only regular files with HexLab's interrupted-save or
retained-previous-version names. Each candidate is opened through the normal
read-only project validation path, including schema, project rows, patch ranges,
and embedded input checks. Unopenable artifacts are skipped. Directory scans
are bounded to 8,192 entries and 256 validated candidates. JSON output reports
the UTF-8 path, project UUID, and artifact kind for each candidate.

Restore one listed artifact to an independent project:

```powershell
hexlab_cli project recovery restore .\projects\.hexlab-save-abc.tmp --output .\recovered.hxproj
```

Restore re-discovers and validates the artifact in its containing directory,
then the database API checks its kind and UUID again before copying it through
the checked Save As path. The new project receives a fresh UUID. The artifact
is retained unchanged. Existing output files are refused unless `--replace` is
explicitly supplied; output paths that alias protected source or project files
are rejected by the database publication layer.

Recovery discovery is not a general damaged-database repair tool. It lists
only complete HexLab staging artifacts that pass ordinary project validation;
corrupt or partial files are not modified or offered for restore. See
[Project format and recovery guarantees](project-format.md).
