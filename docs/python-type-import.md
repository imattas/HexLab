# Python portable type imports

The embedded `hexlab` API supports atomic, name-based import of recursive type
graphs. This is useful for scripts that translate types from a PDB, DWARF tool,
or another project: imports use type names and the destination allocates its own
type IDs, so source project IDs do not leak across projects.

```python
import hexlab

word = hexlab.TypeSpec.integer("u32", 4, alignment=4)
node = hexlab.TypeSpec.structure("Node", [
    ("value", word, 0),
    ("next", hexlab.TypeSpec.pointer(
        hexlab.TypeSpec.named_reference("Node"), 8, alignment=8), 8),
], size=16, alignment=8)

with hexlab.Project.open("sample.hxproj", readonly=False) as project:
    result = project.import_types(
        {"Node": node},
        [(hexlab.Address(0, 0x140001000), "Node")],
        group=10,
    )
    node_id = next(row["id"] for row in result["types"] if row["name"] == "Node")
    project.undo()  # definition and assignment revert together
    project.redo()
```

`Project.import_types(definitions, assignments=(), group=0)` accepts either a
mapping from names to `TypeSpec` values or an iterable of `(name, TypeSpec)`
pairs. Assignments are `(Address, type_name)` pairs. Every named reference may
point to a definition in this batch or an existing project type. The workspace
validates the complete batch before committing it, so an invalid assignment or
duplicate/changed destination does not leave some definitions imported. The
whole import is one normal project-history command; `undo()` and `redo()` keep
definitions and assignments together.

If a destination already has a type with the same name, the import carries the
current destination ID as an optimistic update check and updates the definition
in place. New names receive destination-local IDs. Existing assignments remain
intact unless the incoming batch explicitly assigns another type at that
address. Type origins are not synthesized by this API. Replacing a same-name
definition therefore clears previous source-origin metadata; use native PDB/DWARF
importers when provenance must be retained or refreshed.

Each call is limited to 4096 definitions and 4096 assignments. Individual
`TypeSpec` trees have a nesting limit of 64 and aggregate members, enumerators,
or parameters are limited to 65536 by the native bridge. The returned detached
snapshot contains the project type and assignment tables; it is convenient for
small/moderate imports, while large-table paging is not yet exposed by the
Python API.
