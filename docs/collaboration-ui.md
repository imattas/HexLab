# Desktop collaboration proposals

The File menu's **Review Collaboration Proposals** command opens the durable
proposal inbox for the active saved project. The window refreshes the SQLite
head and pending inbox together, shows each proposal's base, observed and
current revisions, and lists its proposed metadata and analysis-decision edits.

**Accept / Rebase** refreshes again immediately before resolving. For
annotations and bookmarks, it rebuilds each expected-before value from the
current head and applies only fields changed by the proposal, preserving
concurrent edits to untouched fields. If both sides changed the same field,
the proposal remains pending. A deletion is accepted only when the current
entity still matches the proposal's before-value. If the original entity was
removed, an edit is accepted only when an identical semantic value already
exists; otherwise the UI leaves the proposal pending. A deleted entity whose
original ID is already absent is treated as converged. The database API commits the
resolution and marks the proposal accepted as one collaboration resolution
operation. **Dismiss
Proposal** refreshes and records a resolved, unaccepted audit entry without
changing user state.

The database rejects proposals whose base edit revision is newer than the
observed project head instead of storing them as stale conflicts. Conflict IDs
used for preview and dismissal must be nonzero SQLite row IDs representable by
the signed integer key; invalid IDs fail before database access.

Reference decisions merge `source`, `target`, and `kind` independently when
the current row still has the proposal's stable ID. A convergent insertion
with the same `(source, target, kind)` is a no-op; a reused reference ID with
different edge contents, a competing edit to the same field, a stale edit, or
a delete that races with a reinserted edge remains pending. Safe reference,
region, and function insertions receive IDs allocated from the refreshed
project head so concurrent work cannot claim the proposed ID.

Region decisions treat `(begin, size)` as one ownership extent and merge `kind`
separately. Newly introduced extents must stay valid and must not overlap any
other current or accepted region. Function decisions merge suppression and
entry values and combine chunk-set changes only when both peers leave a
base-owned chunk alone, make the same change, or change disjoint ownership
ranges. Conflicting changes to the same base range, duplicate entries, invalid
entry/chunk containment, and newly overlapping chunks owned by different
functions remain in the inbox. These checks use sorted ranges and the full
projected head after all removals and insertions, so ordinary validation scales
with the number of ranges rather than comparing every entity pair. Pathological
overlap queries have a candidate-work limit, and cancellation is checked while
rebasing. A proposal's change ordering does not decide whether a range conflict
is accepted.

Before accepting, the window queues a refresh behind work already submitted to
every open tab for the same project file and UUID, waits for all refreshes, and
then reads the collaboration head again. An in-flight background analysis may
finish later; its source revision is still checked before adoption. This
prevents an already-queued local command in any matching tab from racing the
proposal's edit-revision check.

The project collaboration API automatically rebases nonconflicting annotation,
bookmark, reference, region-decision, function-decision, patch, type-assignment,
and type-definition changes before recording a conflict. Type definitions merge
their name, source origin, and immutable layout as separate fields; concurrent
changes to the same field remain unresolved. New definitions receive IDs from
the refreshed project head, and type assignments in the same proposal follow
that remapping. A definition can be removed only when no current assignment,
debug variable, or named type reference depends on it. Renames are held for
manual review when they would alter a named-reference dependency. Patch edits
merge byte by byte against the original input, and overlapping incompatible
byte changes remain pending. The proposal window still provides explicit
conflict review for annotation and bookmark changes; unsupported or overlapping
structural changes remain pending. The
shared collaboration facade owns its own serialized database connection;
the open document's `ProjectActor` retains its connection and thread ownership.
After an accepted proposal commits, the dialog queues a refresh for every open
tab whose project UUID and underlying project file match the reviewed project.
Each actor refreshes its existing SQLite connection on its writer thread, keeps
its process write lease, and publishes the newly committed snapshot.
Existing desktop navigation/history stays with
the document; invalid selections are repaired by the normal snapshot adoption
path, and search history is cleared only when byte or analysis-decision
revisions changed. If only annotations or bookmarks changed, matching derived
analysis is retained. If bytes or decisions changed, analysis is rescheduled
against the new head. The refresh is asynchronous and reports failures through
the document's normal error state. Dismissing a proposal does not trigger a
project refresh.

The direct handoff covers commits accepted by the collaboration window in the
same desktop process. Open document actors in any process also poll the
project's small revision header once per second and reload a changed head on
their owner thread. The normal refresh verifies project UUID and embedded
input identity before publishing, then preserves navigation when the selected
location remains valid. New conflict-inbox entries are visible when the
proposal window is refreshed; they do not force a project-state reload. This is
local shared-file collaboration and does not provide a network notification
transport.
