# Local PE/PDB binding

PE opening performs bounded, local-only sidecar discovery. It checks the PE's
RSDS CodeView path basename beside the image, then `<image-name>.pdb`; optional
search directories follow in the order supplied. `hexlab_cli project create`
accepts `--pdb <path>` to select one file or `--pdb-search <directory>` for one
additional directory. The same options work with `inspect` and `disassemble`.
The chosen path is stored in the durable project recipe,
so reopening and reparsing use the same local PDB. HexLab never contacts a
symbol server.

Binding requires exactly one PE CodeView identity with the same 16-byte GUID
and age as the PDB info stream. Missing, malformed, mismatched, and matched
PDBs are reported separately. A mismatch never imports any rows. Matching
PDBs contribute supported C13 source-line rows, DBI module and global/public
procedure/data symbols, and supported named TPI records independently, so one unavailable stream does
not discard valid data from another. Symbol and line section coordinates are
converted only when they fit a declared PE section and image extent; otherwise
the original section-relative location remains visible without a guessed VA.
PDB input is capped at 512 MiB. Desktop PE metadata has PDB status, Symbols,
Types, and Source Lines pages; CLI inspection prints status and a bounded
symbol preview.

This imports only the currently supported PDB subset. It does not import
locals, follow global reference records to module definitions, decode the
public/global hash tables, import complete type graphs, or perform network symbol
lookup. A configured local path is persisted as part of the recipe and is
therefore expected to remain available when reopening the project.
