# Desktop workspace persistence

The Strings page retains per-document filters, query, sort order, and semantic
row selection across tab switches and normal workspace session save/restore.
Restoration validates the input/load recipe and, for saved projects, project UUID;
changed scans do not reuse row indices. See [Desktop string browser](desktop-strings.md)
for bounds, selection checks, and session limitations.

The Types and Symbols pane retains its type-definition, importable-symbol, and
assignment filters independently for each open document while switching tabs.
For saved projects, all three filters are also stored under the project's UUID
in the per-user configuration and restored when that project is opened again.
At most 32 project filter sets are retained, and each filter is capped at 2,048
characters when loaded. File-only documents keep their per-document filters in
memory for the current desktop session; the latest filter values also remain
the defaults for the first document opened on the next session.

HexLab stores the desktop frame's normal position and size, maximized state, and wxAUI pane perspective in the per-user wxWidgets configuration under the `Desktop` group. The perspective is restored after the panes are created. `View > Reset Layout` returns to the built-in pane arrangement; closing afterward saves that arrangement as the next startup layout.

Saved geometry is accepted only when its dimensions meet the application's minimum and part of the frame remains visible on a currently attached display. Invalid or off-screen geometry falls back to the standard startup size. A missing or invalid AUI perspective falls back to the current built-in perspective. The saved perspective is capped at 64 KiB.

Open saved projects and imported binary tabs are persisted separately under the per-user `Desktop/Session` configuration group. At most 1,024 entries are retained and restored, with each path capped at 32,768 characters and each encoded loader recipe capped at 64 KiB. When an older or edited session record lists more than 1,024 documents, startup considers the first 1,024 in saved order and reports how many later entries were not attempted; each considered entry is validated independently before its path or recipe is used. The save records how many open documents it could not persist because they had no durable restore source, used an unsupported recipe, or exceeded the session limit; the next startup reports that count. Saved project read-only/collaborative mode is retained. Missing or empty mode fields from older records retain the historical read-write default; an unrecognized non-empty mode is skipped so malformed configuration cannot silently reopen a project writable. Binary tabs restore only when their source path and durable loader recipe are both present; raw mappings, concrete format choices, Mach-O selection, PDB binding, PE runtime architecture, and explicit DWARF supplementary package paths come from that recipe rather than guessed defaults. Projects that cannot be read follow the regular asynchronous project-open error path. Missing paths, malformed records, plugin-backed recipes, and entries without enough durable source information are skipped safely. The previously active persisted tab is selected after restored opens finish when it was among the entries considered and opened. Each tab's current cursor is restored independently when its recorded file offset or address-space/64-bit address still maps in the reopened image, so switching to an inactive restored tab returns to its prior location. Old session records without cursor fields remain valid. Invalid or stale cursor fields are ignored without preventing a document from opening. Transient pages and unsupported unsaved documents are not persisted. This session record is independent of the wxAUI perspective and frame geometry settings.

Saved `.hxcmp` comparison windows are also retained in the per-user session,
up to 32 windows. This includes windows opened from a saved file or a live
comparison that was saved with **Save Comparison Session As**. Startup reopens
each saved comparison file and skips missing or invalid sessions without
preventing project and binary tabs from restoring. Live comparison windows
that have not been saved remain transient.
