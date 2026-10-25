# FLAIR catalog sets in the project CLI

`project flirt` and `project flirt-apply` accept either one catalog through
`--definitions` or an ordered path list through `--definitions-list`.

The list is UTF-8 text, limited to 1 MiB. Each nonblank line names one `.pat`,
`.pat.gz`, or `.sig` file. Lines whose first nonspace character is `#` are
comments. Relative catalog paths resolve against the list file's directory.
Catalog order is preserved, and each candidate's provenance includes its list
entry so catalogs from different libraries remain identifiable.

All catalogs must match the loaded image's architecture and execution mode.
The list is limited to 256 catalogs. Catalog input bytes, compressed-body
expansion, and pattern counts have aggregate limits; candidate, comparison,
reference, function, and result budgets apply to the combined recognition pass.
The catalogs share cross-catalog reference resolution. An empty list is
rejected.

For example, `libraries.txt` may contain:

```text
# common runtime
runtime.pat.gz
../sdk/ui.sig
```

```text
hexlab_cli project flirt target.hxproj --definitions-list libraries.txt --provenance "vendor SDK 4.2"
```

`flirt-apply` stores source-bound evidence for the entire ordered set. It only
renames functions when `--rename-unique` is explicit and recognition completes
with a single unique public name at that function.
