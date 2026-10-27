# Portable type libraries

The CLI exchanges editable project types, their DWARF declaration origins, and compatible type assignments without project IDs:

```text
hexlab_cli project types export sample.hxproj --output sample.hxtl
hexlab_cli project types import other.hxproj --input sample.hxtl
```

The binary `HXTL` format is versioned, little-endian, and length-prefixed. Version 4 is written by export; version 2 address-assignment bundles, version 3 file-offset bundles, and version 1 definition-only files remain readable. A bundle contains up to 4096 unique named definitions, canonical type records, declaration kind, and optional DWARF origin offsets. Versions 2 through 4 also record the input size and SHA-256 plus a SHA-256 of the encoded load recipe. Version 3 adds file-offset assignments while retaining the version 2 address-assignment encoding. Version 4 appends SHA-256 over the complete preceding bundle bytes; decoding verifies it before parsing records. This detects accidental corruption but is not a signature or publisher-authentication mechanism. Type assignments refer to definitions by name and can be imported only when both source identity hashes match the destination project. Virtual-address and file-offset locations are supported. Conflicting assignments fail by default; pass `--replace-assignments` to replace them. If only the definitions are wanted from a bundle with assignments whose source identity differs, pass `--skip-assignments-on-mismatch`.

The complete file is limited to 16 MiB, names to 512 bytes, definitions to 4096, and assignments to 262144. Every record is decoded and validated before the workspace import command runs. A graph-aware resolver validates named references across every nested type edge, including member, parameter, method, virtual-base, static-data, result, and element types. It accepts only exact names present in the bundle or destination and stops after one million unique type nodes or four million reference edges. Imports are one atomic, undoable project command. Matching names update in place; new names receive destination-local IDs. References remain symbolic by name, so nested types and forward references work when their targets are included in the bundle or already exist in the destination. Unknown references are rejected before workspace commit. Version 1 bundles contain definitions only.

This workflow handles the project type model, including aggregate layout, function types, enum values, qualifiers, methods and static data attached to declarations. It is not a compiler header/library importer and does not transfer project-local IDs or debug-variable records. Use native PDB/DWARF import for debug variables.
