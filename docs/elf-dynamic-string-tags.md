# ELF dynamic string tags

The loader resolves these `PT_DYNAMIC`/`.dynamic` string-table references using
the validated `DT_STRTAB` and `DT_STRSZ` bounds:

| Tag | Meaning retained |
| --- | --- |
| `DT_NEEDED` | Required library name |
| `DT_SONAME` | Shared-object name |
| `DT_RPATH`, `DT_RUNPATH` | Search-path strings |
| `DT_CONFIG` | Configuration-file name |
| `DT_DEPAUDIT`, `DT_AUDIT` | Audit-library names |
| `DT_AUXILIARY`, `DT_FILTER` | Auxiliary or standard filtee names |

Each string is required to start within the bounded dynamic string table and
terminate before its end. Repeated `DT_NEEDED`, audit, and filter entries are
retained in file order. Other understood scalar dynamic tags remain singleton
and duplicate instances are malformed. The CLI prints labels and text for the
supported string tags, retaining the original dynamic-entry index and raw
string-table offset in metadata.

This is metadata inspection only. HexLab does not load dependencies or
filtees, apply runtime search precedence, consume configuration files, or run
runtime-auditing callbacks.
