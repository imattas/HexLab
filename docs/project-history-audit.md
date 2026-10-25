# Project history audit

`ProjectStore::audit_history(expected_edit, after_step, limits, stop)` checks a
bounded page of a project's durable undo/redo log without changing the project.
It is available in read-only, read-write, and collaborative modes. The caller
starts with `after_step = 0`, retains the returned `source_revisions.edit` as
`expected_edit`, and continues from `next_after_step` while `has_more` is true.
If another writer edits the project, the next page returns a revision conflict
and the audit should restart from a fresh project snapshot.

For every entry in the page, the audit checks the ordered step, the group ID,
and the metadata flag values. It reads both forward and inverse payloads,
checks their chunk ordinals and extents, decodes them, and verifies that the
inverse payload matches the inverse of the forward delta. The page reports the
project UUID, source revisions, history cursor and count, entries verified,
aggregate delta bytes read, and whether another page remains.

The defaults are 256 steps and 16 MiB of payload bytes. A page can request at
most 4096 steps and 128 MiB combined across both directions. Exceeding either
accepted budget fails the page without returning partial results; retry from
the same cursor with a larger budget. A zero-step limit returns an empty page
and leaves the cursor unchanged, which can be useful for reading current audit
metadata without inspecting payloads.

The audit verifies payload structure and inverse pairing. It does not replay
all commands against the current user state or prove the current state matches
the history cursor. Exact-step preview performs bounded replay and validates
the state preconditions for the traversed interval.
