# Native hardware watchpoints

The desktop debugger can create write and access watchpoints alongside
hardware execute breakpoints. Select a watchpoint kind, set the watched address,
and choose a length. The breakpoint list retains the kind and byte length. A
saved disabled watchpoint is restored disabled when the backend supports
hardware toggling; it does not consume an active hardware slot.

On native Windows and Linux x86-64 targets, data watchpoint lengths are 1, 2,
4, or 8 bytes. The address must be aligned to the chosen length. Hardware
execute breakpoints and data watchpoints share four debug-register slots per
thread. Edits require the target to be stopped. Windows updates the active
thread contexts as a transaction; Linux x86-64 requires every traced thread to
be stopped and restores earlier thread contexts if a later update fails.

x86/x64 debug registers support write-only and read/write data conditions, but
not a read-only condition. The native backends reject `BreakpointKind::read`
instead of silently treating it as read/write. Choose **Hardware access** to
stop on reads and writes, or **Hardware write** to stop on writes. Other
backends may implement read-only watchpoints when their target protocol or
architecture supports them.

Invalid lengths, misaligned addresses, exhausted slots, preexisting unowned
debug-register state, and unsupported watchpoint kinds produce explicit errors.
Project watchpoints that a backend cannot install are skipped during project
breakpoint application and reported in the summary; their saved project rows
are not rewritten.
