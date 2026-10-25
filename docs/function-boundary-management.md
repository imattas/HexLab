# Manual function-boundary management

Projects persist manual function decisions as history-backed function overrides. Define a new entry with `project define --at va:<address> --kind function`; define or resize a multi-range function with `--kind chunks --chunks va:<address>+<size>[,...]`; and suppress or restore a candidate with `--kind suppress` or `--kind unsuppress`.

To remove the stored override and return that entry to normal automatic recovery, use:

```text
hexlab_cli project undefine <project.hxproj> --at va:<function-entry> --kind function
```

This command requires a persisted function decision and is undoable through ordinary project history. Resetting a suppression may make an automatically recovered function visible again. It does not delete analysis-derived function results or erase prior history.

In the desktop application, select the function entry and use **Edit → Reset Function Override**. The action is enabled only when the selected address has an explicit persisted function decision and the project is writable.

Function entries must be decodable instruction boundaries. Entries in non-executable mappings require a prior explicit code-range decision. Explicit chunks are bounded, mapped ranges in the entry's address space and must include the entry. Ambiguous or invalid ranges are rejected before a history step is created.
