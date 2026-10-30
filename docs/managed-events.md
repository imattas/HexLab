# CLR event metadata

`parse_managed_events` reads EventMap, EventPtr, Event, and MethodSemantics
records from a CLR metadata root. It validates row extents, pointer-table
permutations, owner ranges and boundaries, TypeDefOrRef event-type tokens,
and event accessor ownership. AddOn, RemoveOn, Fire, and Other method roles
are preserved with metadata tokens and root-relative row offsets. Add, remove,
and fire roles are unique per event; repeated Other methods are permitted.

`inspect_managed_events` exposes the same catalog from a loaded PE. The CLI
command `hexlab_cli project events <project>` reports up to 128 events and 16
accessors per event. It does not execute accessor methods or resolve event
types across assemblies.

The parser bounds the metadata root to 64 MiB, Event and EventMap rows to
65,536 each, MethodSemantics rows to 250,000, and cumulative event-name bytes
to 8 MiB. Individual names are limited to 4,096 bytes. Invalid pointer maps,
tokens, table layouts, duplicate roles, or accessors declared on another type
make parsing fail with a diagnostic. Generic accessor signature validation
and custom attributes remain outside this feature.
