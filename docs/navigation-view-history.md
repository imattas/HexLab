# Navigation history restores the originating view

Navigation history records the active binary workspace view alongside each accepted location. Back, Forward, and the navigation-history chooser restore both the address and the view where that address was visited. The chooser labels entries with their view, such as `Disassembly`, `Bytes`, `Graph`, `Pseudocode`, or `Source`.

History remains scoped to the open document and its analyzed project revision. Entries from changed immutable document revisions, changed project UUID/input fingerprints/revisions, and unmapped locations are skipped. The history stores at most 512 entries.

At desktop shutdown, history entries for saved projects are stored in the desktop configuration. Each stored row contains the project UUID, exact input size and SHA-256, edit/byte/decision revision tuple, location, and originating binary view; it does not persist an ephemeral document ID. On a later run, the row is rebound only to an open project with the same UUID and input fingerprint and the exact saved revision tuple. The location is then checked again through normal document navigation before it is restored. This permits history to survive reopening the same project while rejecting a project that was edited, replaced, or no longer maps the old location. Unnamed or unsaved documents keep in-memory history only.

The location remains the shared workspace selection, so restoring an entry synchronizes the other location-aware panes to the restored address while returning focus to the recorded notebook view.

The Navigate menu's **Export History...** command writes the retained entries
to UTF-8 CSV or versioned JSON (`hexlab.navigation-history`, version 1). Both
formats record the current cursor, document ID and open document path when
available, formatted location, originating binary view, and saved-project
UUID/input fingerprint/revision tuple when those values exist. This lets users
keep an audit of file-only and unsaved-document navigation even though that
history is not restored after restart. Export preserves entries as recorded;
it does not assert that a closed document or location can still be reopened.
JSON represents absent paths and project identities as empty strings and null,
respectively, and records the current entry index explicitly.
