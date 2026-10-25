# RSP process-qualified thread selection

The RSP client validates `Hg` selectors separately from concrete thread IDs.
Concrete IDs such as `p2a.4` remain required for stop replies, thread
enumeration, and exact `vCont` actions. The `Hg` packet also accepts the
protocol's selection forms `0`, `-1`, and `pPID.-1` (or `pPID.0`) for a
process-wide/general-thread selection.

This distinction matters when returning to an inferior that is already
attached on an extended-remote connection. HexLab selects that process with
`HgpPID.-1`; treating the selector as a concrete thread ID would reject it
before transmission, despite it being a valid GDB remote selector. PID zero,
empty components, malformed hexadecimal IDs, and zero concrete process or
thread IDs remain invalid.

Selection does not attach or resume a process. It only changes the remote
stub's general-thread context for subsequent register or memory operations.
Process attach continues to use `vAttach;PID`, and concrete per-thread resume
continues to use a qualified `vCont` action.
