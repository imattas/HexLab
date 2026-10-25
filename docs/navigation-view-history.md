# Navigation history restores the originating view

Navigation history records the active binary workspace view alongside each accepted location. Back, Forward, and the navigation-history chooser restore both the address and the view where that address was visited. The chooser labels entries with their view, such as `Disassembly`, `Bytes`, `Graph`, `Pseudocode`, or `Source`.

History remains scoped to the open document and its analyzed project revision. Entries from closed documents or changed project revisions are skipped. The history stores at most 512 entries.

The location remains the shared workspace selection, so restoring an entry synchronizes the other location-aware panes to the restored address while returning focus to the recorded notebook view.
