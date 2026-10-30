# HexLab project format

Projects use SQLite with application ID `0x48584C42` and schema version 18. The authoritative schema and validation live in `libs/database/src/schema.cpp`; `ProjectStore` is the supported writer. Unknown schema objects, incompatible versions and malformed records are rejected. Every open runs SQLite `integrity_check(1)` and the foreign-key check before loading project state, so persisted B-tree damage and violated SQL checks are rejected without migration or repair. Older schemas migrate transactionally through v18 when opened writable or collaborative; read-only opens validate and read older supported schemas without modifying them. A writable open rechecks the validated project's UUID after reopening the file, before migration, so replacement between the read-only probe and writer connection fails as a conflict rather than attaching the old lease to a new project. Schema v8 appends a checked declaration role (`type`, `object`, or `function`) to named type definitions; old rows default to `type`. Schema v9 adds project breakpoint records. Schema v10 appends condition text, logpoint mode and literal message, and the configured ignore threshold; old rows receive empty/false/zero defaults. Schema v11 adds the persisted runtime hit count to breakpoints, defaulting existing records to zero. Schema v12 adds bounded loader and runtime-relocation diagnostic rows, replaced atomically after successful loading. Schema v13 adds a bounded latest type-import diagnostic report; a completed header or PDB import replaces it outside user edit history. Schema v14 adds bounded stable issue identities for findings the user marked reviewed; review state does not create edit-history entries. Schema v15 adds source AnalysisKey provenance to type-import diagnostics and v16 adds bounded project preferences; v17 adds a persisted project-breakpoint one-shot flag that defaults to false. Schema v18 adds optional Unix-millisecond creation times to history entries; existing rows remain undated. User-state/history codec v10 retains decoding for older versions and carries breakpoint rules in reversible history payloads. Do not edit a live database with another SQLite client.

The `project` singleton stores a native UUID, canonical load recipe, input size/SHA-256, monotonic edit/byte/decision revisions, history cursor and allocation cursor. Unsigned 64-bit values are eight-byte big-endian blobs, including addresses above INT64_MAX. Typed locations distinguish virtual addresses with an address-space ID from file offsets; they are never interchangeable display strings.

ARM raw load recipes use bytes `03 00 06`, a four-byte big-endian text length,
and canonical `hexlab-arm-profile 1` text. The payload embeds declarations, not
an external path. Truncation, surplus bytes, noncanonical text and out-of-budget
records are rejected. Old flat, segmented-x86, ELF, PE and Mach-O recipe bytes
retain their previous encodings. Recipe changes participate in analysis keys;
generic image-profile validation does not prove ELF/platform source records.

`input_chunks` embeds the original input in contiguous chunks of at most 1 MiB. Reopening streams and verifies these bytes into an owned mapped backing; it does not need the original external file. `input_provenance` retains native path encoding and an optional relative path as provenance, not input authority. Native Windows paths are retained as UTF-16LE bytes.

`annotations`, `bookmarks`, `regions`, `functions`, `function_chunks` and `explicit_references` hold user intent. `type_definitions` stores named canonical immutable type graphs and optional DWARF source origins (source identity, section, unit offset, DIE offset, and DIE size); `type_assignments` binds a definition ID to an address location with a foreign key. Older projects migrate with empty origins, and user-state history payloads preserve origins through undo/redo. The public workspace commands can define types, assign/remove assignments and import available image symbols as names; the desktop has no dedicated type editor yet. Type graphs are bounded to 16 MiB each and depth 128. `patches` contains canonical nonoverlapping same-length original/replacement spans of at most 1 MiB each. Patches overlay embedded input; they do not modify its original chunks. User collections are bounded to 100000 records each with a combined 64 MiB loading budget. Names and labels are at most 512 UTF-8 bytes; comments at most 1 MiB. Names are unique within a virtual address space.

`history` and chunked `history_payload` hold grouped reversible deltas for annotations, decisions, patches, type definitions and type assignments. Expected-before checks and revision compare-and-swap run inside the writer transaction. Undo/redo never decrease revisions or reuse allocation IDs; a new edit after undo removes the redo branch. Runtime history count is derived from history rows rather than stored as another schema field.

If SQLite cannot roll back a transaction that failed or was canceled, the connection is marked unusable. Subsequent statements, transactions, checkpoints, and backups return an integrity error with the SQLite rollback code instead of running against an unknown transaction state. Close and reopen the project to recover a fresh connection; the failed operation never publishes a new in-memory project snapshot.

`derived_cache` holds optional versioned reference or complete-derived payloads, limited to 64 MiB per payload. Cache keys bind input identity, recipe, engine and byte/decision revisions. Checksums detect corruption; they are not authenticity signatures. Complete-derived format11 binds the envelope and canonical instruction records to loaded architecture/mode/byte order, domain contexts and mapping identity, including typed ARM operands and instruction-control metadata. Earlier derived formats recompute without user-schema migration. Cache loading validates raw/typed instructions with canonical decoding, rewalks ownership/references and rescans strings. Thumb instruction-state wire consistency does not yet establish an actual source-bound IT chain; automatic mixed ARM analysis remains guarded pending that integration. Standalone reference formats7/8/9 remain inspectable under their original identities. Separate counters distinguish recovery work from cache validation. Invalid caches recompute; readonly sessions do not repair them. Cache write failure cannot roll back an accepted user command.

Connections enable WAL, foreign keys and FULL synchronous mode with bounded busy handling. One actor owns each writer connection. A native advisory process lease makes a second ordinary editable open readonly. `ProjectCollaboration::open` opts into multiple local editable sessions and records any CAS-rejected proposal in the durable collaboration inbox. SQLite serializes writers; edit revisions and expected-before values reject stale updates. Open document actors make a bounded, one-second header-revision probe and automatically reload a changed shared project on their owner thread. The probe materializes no project payload; the full refresh still verifies project UUID and embedded-input identity before publishing. Collaborators inspect pending proposals, call `refresh` to obtain the latest head snapshot, rebase a chosen proposal, then resolve it with a normal project commit; dismissed proposals remain in the audit list. This is local shared-file collaboration and does not define a network protocol or merge binary patches automatically. Readonly commands do not acquire the editable lease or write caches. Live WAL/SHM files are part of a working SQLite database: copy with Save As, not by copying only its main file while open.

`ProjectStore::refresh_external(stop)` pins schema, user rows, and patch
validation to one deferred SQLite read transaction. It accepts committed edits
to the same logical project and embedded-input identity. A changed UUID or
input size/SHA-256 returns `conflict` before extracting replacement input or
adopting the new state; the caller must close and reopen to inspect that
different project. Identity rejection leaves the previous snapshot and cached
input intact, including when the store is used directly without a desktop
actor. A canceled or failed refresh uses the transaction's native rollback,
which remains available after the operation's stop token is canceled. The
existing connection is therefore reusable for a later refresh or command
rather than being stranded inside the canceled read transaction. Successful
refresh still publishes the new immutable state only after the read transaction
commits; no schema or history-format change is involved.

Save As uses SQLite backup and checked native publication, assigns a new project UUID and then adopts the saved store. Publication protects source, original input, backing files, journal companions and native hard-link identities. Existing output replacement must be explicit. On POSIX, after the SQLite backup is checkpointed and the atomic rename publishes it, the containing directory is synchronized before Save As reports success, so the rename itself is included in the filesystem durability boundary. A failure to synchronize is reported as an error that explicitly says the project was already published; recovery can inspect and reopen that complete destination. Windows publication requests write-through behavior from the native move operation. A native publication failure that cannot restore its previous destination retains a named recovery copy; the error reports that path. Patched binary export streams effective bytes with a receipt and SHA-256 and leaves the project and original input untouched. Embedded signatures and checksums are not repaired automatically.

`ProjectStore::discover_recovery_candidates(directory, stop)` scans a bounded directory for `.hexlab-save-*.tmp` interrupted Save As outputs and `.hexlab-previous-*.tmp` retained prior versions. It opens each candidate read-only through the normal schema, row, patch and embedded-input validation path, returning only projects that fully validate and their UUIDs. Unopenable or corrupt artifacts are skipped; cancellation and directory enumeration failures are reported. The scan is capped at 8,192 entries and 256 candidate artifacts. Discovery never renames, deletes, or replaces files. A returned candidate may disappear if another process is completing or cleaning up the corresponding Save As operation; callers should revalidate it before offering recovery actions. `ProjectStore::recover_candidate(candidate, destination, policy, stop)` reopens the selected artifact, verifies its kind and UUID still match discovery, then publishes a validated Save As copy to the requested destination. Replacement must be explicitly selected by the caller. The source artifact stays intact, and the new destination receives a fresh UUID so it is an independent project identity. Recovery uses the same checked SQLite backup, embedded-input verification, and atomic publication path as Save As; it does not mutate the artifact or automatically recover anything.

`ProjectStore::recover_candidate_in_place(candidate, target, stop)` restores a
discovered `.hexlab-previous-*.tmp` artifact over the same project identity.
Interrupted Save As artifacts are rejected because Save As assigns them a new
UUID. The API reopens the candidate, checks its UUID and edit/byte/decision
revisions against the discovery record, verifies that the closed target still
has the expected project UUID, acquires the target's ordinary project lease,
and checks the target revisions again before publication. The restore keeps the
project UUID and retains the recovery artifact. Callers must close project
stores before restoring and reopen the target afterward to refresh in-memory
state. This restores a validated prior snapshot; it is not history replay and
does not repair a damaged target database.

After a desktop project-open failure, HexLab searches the selected file's directory in a background task. If validated candidates are found, a modal selection lists their artifact kind and full path alongside the original open error. The selected path is submitted through the ordinary project-open flow, which revalidates it. Cancel leaves all files untouched; no candidate is automatically adopted, renamed, deleted, or overwritten.

`ProjectStore::check_integrity(expected_edit, max_issues, stop)` runs SQLite's
`integrity_check` and `foreign_key_check` against one deferred read snapshot.
The requested edit revision must still match when that snapshot is pinned;
otherwise the call returns a conflict and should be retried after refresh.
Issue collection is capped at 256 messages of at most 4 KiB each. When the
limit is reached, `complete` is false and `consistent` is false because further
violations may exist. The operation is read-only, observes cancellation, and
never repairs or rewrites the project. It detects database-level consistency
problems but does not replace the loader's schema, row, patch, embedded-input,
or history validation, and it cannot recover damaged data.

An invalid patched header preserves file-only effective bytes and orphaned virtual annotations. It does not silently reinterpret the input as raw. Undo can restore the mapping. Derived pending/stale/partial states remain visible; retained facts are not labeled fresh until their complete source key matches.

Migration and process-kill tests cover the recorded transaction and publication checkpoints. This is evidence for process termination, not physical power loss, every filesystem failure or an untested platform. See [validation](project-analysis-validation.md) and [CLI commands](project-cli.md).

Project reliability remains partial: physical power-loss and filesystem-fault
coverage across supported platforms, general damaged-database repair, schema
downgrade/export compatibility, and recovery of incomplete/corrupt staging
artifacts are not established by the current transaction and publication
workflow.
