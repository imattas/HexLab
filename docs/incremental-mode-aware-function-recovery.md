# Mode-aware incremental function recovery

Incremental recovery can retain an instruction fact only when its starting
context and Thumb IT input match the current image. It now also checks the
context of every byte consumed by that fact. A profile edit that moves an
execution-mode boundary through an instruction rejects that fact and decodes
from the new context.

Fresh decoding uses the same boundary rule while collecting candidate bytes.
The decoder does not consume bytes across an architecture or execution-mode
boundary, and reports a bounded chunk stop when the candidate instruction is
truncated there. Roots, CFG edges, ownership, and function records continue to
be reconstructed for each reanalysis, so a context/profile change cannot keep
old roots or mode-dependent edges attached to a new snapshot. Facts whose byte
ranges and per-byte contexts remain valid are still eligible for reuse.

Cancellation remains cooperative: each per-byte context lookup uses the
existing stop-aware image access path. The function engine fingerprint is
advanced so persistent snapshots produced by the prior boundary behavior are
not reused.
