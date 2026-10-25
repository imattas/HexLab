# Module dependency inventory

`hexlab_cli modules <binary>...` loads each supplied image without running analysis and prints dependency names found in the parsed metadata. PE imports, ELF `DT_NEEDED` entries, and Mach-O library load commands are included. Each dependency is marked resolved when exactly one other supplied file has a matching case-insensitive basename, ambiguous when multiple supplied files match, or unresolved when no supplied file matches.

This is a file-set inventory, not a system loader simulation. It does not search host library paths, validate ABI compatibility, resolve individual imported symbols, or recursively discover files. Missing or malformed inputs report the loader diagnostic and stop the command. Inputs must contain at least two paths so there is a candidate set to resolve against.

Example:

```text
hexlab_cli modules app.exe vendor.dll
```
