# Static UEFI protocol-effect planning

`plan_uefi_protocol_discovery` adds bounded iterative planning to the existing
same-volume DXE/UEFI driver inventory. It accepts an initial available-GUID set
and `UefiDriverProtocolEffect` rows identifying each file's **assumed** protocol
installs, with caller-provided provenance text. The library does not derive
these effects from machine code, invoke a driver or observe installations.

`plan_uefi_pei_protocol_discovery` applies the same explicit-assumption model
to PEIM and combined PEIM/DXE files (`0x06`, `0x08`), using caller-supplied PPI
GUID effects. Each round chooses the first currently ready PEIM in firmware
volume order, adds only that file's newly assumed PPIs, and reevaluates PEI
DEPEX. It does not infer PPIs from PEIM code or model PEI dispatcher policies
such as apriori ordering, shadowing, or dispatch notifications. The result uses
the same `UefiProtocolDiscoveryPlan` shape: step rows identify file and DEPEX
section provenance, while the available-GUID field represents assumed PPI
state for this API. Only a no-ready-module snapshot produces final blocked
entries; round/work limits do not publish stale readiness rows.

Each round evaluates the existing DEPEX/order plan against the current assumed
GUID set, chooses at most one eligible driver, adds that driver's declared new
GUIDs, and starts another round. Every driver is chosen at most once. Missing
effect rows add no protocols. Duplicate GUIDs do not create repeated additions.
Reevaluation after every step also handles `NOT` expressions: readiness from an
earlier snapshot is never used after a protocol assumption changes.

Driver selection preserves stable existing snapshot order and checks all
same-volume `BEFORE`/`AFTER` predecessors, including predecessors whose boolean
dependencies are currently false. A `BEFORE` owner also waits for its target's
snapshot readiness. Missing or ambiguous target file GUIDs, cycles and blocked
predecessors remain unresolved. These are conservative relative-order
recommendations; immediate-before/after execution adjacency and the full PI
dispatcher's scheduling rules are not certified. `SOR` drivers remain blocked
because this API has no caller dispatch-request context. Multiple DXE DEPEX
sections on one driver are rejected as unsupported rather than combined by
guessing. Driver eligibility otherwise follows the existing file-type
`0x05`-`0x07` and data-valid-state rules.

`assumed_steps` retains round number, file index/GUID, checked original file
header offset, contributing DEPEX section indexes, newly assumed GUIDs and the
effect provenance. Section indexes refer to the original file's section rows,
whose offset-space and parent records distinguish physical source bytes from
decompressed streams. `assumed_available_guids` starts with unique input GUIDs
and appends unique assumed additions. These fields never report observed
installations.

The result distinguishes a reached `fixed_point` from `round_limit` and
`work_limit`. `remaining_file_indices` identifies drivers not selected.
`blocked_entries` is populated only from a final fully evaluated fixed-point
snapshot, preventing stale readiness diagnostics from being presented after a
limit stops the plan. Malformed caller metadata, cancellation and input limits
return explicit errors.

Both APIs cap a plan at 4096 files, 4096 initial GUID rows, 4096 effect rows,
4096 total effect-GUID rows and 4096 unique available GUIDs. It also caps
sections at 65,536, DEPEX bytes at 4 MiB, each provenance/DEPEX diagnostic at
4096 bytes and each aggregate text category at 1 MiB. Options default to
256 rounds and 64 Mi work units and may be raised only to 4096 rounds and
256 Mi work units. Coarse work charges cover validation, repeated file/order
scans, dependency bytecode, GUID searches and availability-set sorting; limits
are checked before a snapshot is evaluated. Existing per-expression DEPEX
limits still apply. Cancellation is checked between validation records and
rounds. The input volume and all caller effects remain unchanged.

Binary-derived protocol effects, cross-volume dispatch, complete PEI/MM
scheduling, a priori policy, driver loading/execution and security-policy
approval remain unsupported. CLI inventory is unchanged; these APIs serve
callers that already have explicit protocol/PPI-effect assumptions.

The underlying DEPEX and ordering meanings follow the
[PI DXE Dispatcher specification](https://uefi.org/specs/PI/1.8/V2_DXE_Dispatcher.html).
The fixed-point assumption model is a HexLab analysis facility, not an
implementation of that runtime dispatcher.
