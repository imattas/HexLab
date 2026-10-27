# Desktop project history audit

The project History tab can audit stored undo/redo history without changing the live project. Wait for the history count to load, then choose **Audit history**. The button changes to **Cancel audit** while work is in progress.

The view submits revision-pinned audit pages through the project actor and reports progress as each page completes. Each page uses the database defaults of at most 256 history steps and 16 MiB of combined forward/inverse payload data. Paging continues from the exclusive step cursor until the durable history is checked or an error, revision conflict, cancellation, or resource limit stops the audit. A completed audit reports the verified step count, checked delta bytes, and current cursor. **Copy audit result** copies the latest pass, cancellation, or failure summary (capped at 4096 characters) so it can be recorded or shared after the status line changes.

The audit validates stored step continuity, flags and group metadata, payload chunk layout, both delta directions, and the canonical inverse relationship. The operation is read-only. It does not replay the entire active branch against the current user state or repair corrupt history; use the CLI's explicit `--verify-replay` mode for its stronger applied-branch check.
