# Desktop project history audit

The project History tab can audit stored undo/redo history without changing the live project. Wait for the history count to load, then choose **Audit history**. The button changes to **Pause audit** while work is in progress.

Use **Filter loaded steps** to narrow the history table by step number, group ID,
change category (`bytes`, `decisions`, or `metadata`), or state (`applied` or
`redo`). Filtering is local and case-insensitive; it searches every page already
loaded in the table and does not fetch additional history. Clear the field to
restore all loaded entries. Selecting a filtered row still opens that step's
normal read-only preview.

The view submits revision-pinned audit pages through the project actor and reports progress as each page completes. Each page uses the database defaults of at most 256 history steps and 16 MiB of combined forward/inverse payload data. Paging continues from the exclusive step cursor until the durable history is checked or an error, revision conflict, cancellation, or resource limit stops the audit. **Pause audit** retains the last fully verified cursor and aggregate counts; **Resume audit** continues after that cursor, provided the project identity and edit revision remain unchanged. Refreshing history or opening a different revision discards the saved progress. A completed audit reports the verified step count, checked delta bytes, and current cursor. **Copy audit result** copies the latest pass, pause, or failure summary (capped at 4096 characters) so it can be recorded or shared after the status line changes. **Copy audit JSON** copies a `hexlab.history-audit.v1` object with project UUID, edit revision, history cursor/count, resumable audit state, structural/replay status, verified steps/bytes, source-identity-check result, and the bounded human-readable summary. It is capped at 64 KiB and does not modify the project. **Save audit report...** writes the captured result to a user-selected UTF-8 text file together with the project UUID, edit revision, cursor, history count, and whether applied-branch replay was requested. The report is capped at 16 KiB and published atomically; the project database and protected input paths cannot be selected as the destination. If project identity, revision, history cursor/count, replay setting, or audit result changes while the save dialog is open, the save is canceled rather than writing stale report details. Saving a report does not modify the project.

The structural audit validates stored step continuity, flags and group metadata, payload chunk layout, both delta directions, and the canonical inverse relationship. For each audited step it also checks every matching payload row's side, ordinal, data storage type, and chunk extent, so malformed extra sides and invalid metadata cannot be silently skipped by the forward/inverse readers. A bounded indexed check also rejects orphan payload keys and history entries beyond the durable count. The operation is read-only. Structural validation alone does not prove that the current user state agrees with its applied history cursor.

The first audit page also checks the currently recorded external source file when its path is available. It compares the current file's size and SHA-256 with the input identity pinned in the project, reading at most 256 MiB on the project actor's worker. The report distinguishes a match, mismatch, unavailable path, missing path, and files over the check limit. A match describes only the bytes read now; it does not establish what the source file contained when the project or history was created.

The **Current source integrity** line beside the audit status presents that result independently from the structural-history summary. It remains visible when the main status line changes (for example, after copying the report). Before the first audit page completes it says the check has not run yet. Refreshing history resets it. The check is read-only and runs on the serialized project worker; it does not change project history or source provenance.

Enable **Verify applied branch replay after structural audit** before starting
to request the stronger check also available through the CLI's
`--verify-replay` mode. After every structural page passes, the view submits a
revision-pinned exact-step preview of step zero through the same project actor.
This reverses the applied history from the durable cursor and requires the
projected `UserState` to be empty. It checks replay preconditions against the
current stored state without moving the live history cursor or adopting the
projection. The preview is limited to 4,096 applied steps and 64 MiB of inverse
delta payload; exceeding either budget is reported as an incomplete replay,
even if structural audit succeeded. A nonempty step-zero state is a replay
failure. The final result reports structural entry/byte counts and separate
replayed-step/byte counts, and only reports combined success when both stages
pass.

**Pause audit** also cancels an in-progress replay request. **Resume audit**
retries the replay from the pinned current state when all structural pages
were already verified; it does not recount those pages. Replay itself is a
single bounded projection and does not resume halfway through its inverse
deltas. The option remains locked while an audit has resumable progress;
choose **Refresh history** to discard that progress and change audit mode.
Identity, edit-revision, history-count, or cursor disagreement rejects the
replay result. Project/revision changes clear the saved stage and progress.
The mode is a session-local view setting and changes no project records.

Redo-only history entries receive structural checks but are not replayed by
the optional applied-branch check. Structural and replay checks do not prove
historical external source-file integrity, provide unbounded replay, or repair
arbitrary corrupt history.
