# DEX methods in reachable analysis

Reachable instruction analysis queues every validated DEX method with a local
code body as a root, matching function discovery. It also follows exact
`invoke-direct`, `invoke-static`, `invoke-direct/range`, and
`invoke-static/range` method IDs when the referenced method has a validated
local body in the same DEX metadata. Reached direct-call targets are included
in the candidate list.

`invoke-virtual`, `invoke-interface`, and `invoke-super` remain unresolved
because they require receiver or class-hierarchy dispatch. Missing, imported,
or invalid method IDs do not produce local targets. The analysis does not
execute DEX code or infer method reachability from reflection, native bridges,
or runtime registration.
