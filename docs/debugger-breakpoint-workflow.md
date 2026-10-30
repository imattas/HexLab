# Debug-session breakpoint inventory

`DebugSession::breakpoints()` returns the breakpoints successfully installed through that session, in creation order. Software and hardware breakpoint records share the same `Breakpoint` shape and identifier namespace. A failed backend add is not recorded. Removal requires a breakpoint identifier owned by the current session; a failed backend removal leaves the record visible so a caller can retry. Session-owned software and hardware breakpoints can be disabled and re-enabled without changing their identifiers on backends that implement the operation. Disabling a software breakpoint restores the byte that was present before the trap was installed; re-enabling reinstalls the trap. Its original-byte record stays attached, so edits made while it is disabled become the byte restored on final removal. Hardware toggles remove or reinstall only the owned debug-register slot or remote breakpoint tuple. Toggle failures leave the session inventory unchanged. Linux x86-64, Linux AArch64, Windows, and RSP support hardware toggles; Darwin and Linux i386 support software toggles only.

The inventory is cleared when a target is launched, attached, or connected, after a successful detach, and after a process-exit event is successfully acknowledged. It is a session-owned view of requested debugger breakpoints, not an enumeration of breakpoints set by another debugger or directly through a backend outside the session.

The session tracks a runtime hit count for every breakpoint it owns. Call `set_breakpoint_ignore_count(id, n)` to automatically acknowledge and continue the first `n` matching owned hits; a count of zero reports every hit. If one stop event matches several owned breakpoints, each distinct ID is counted once and the event is reported as soon as any matching breakpoint is past its ignore count. Events without owned breakpoint IDs are never suppressed. Hit counters last only for the current debug session and always restart at zero. The configured ignore threshold is saved with project breakpoints; each applied runtime breakpoint begins with a fresh counter.

`set_breakpoint_condition(id, expression)` configures a condition. `set_breakpoint_logpoint(id, true, message)` configures a logpoint. These setters require an owned target session in the running or stopped state; calls after exit or detach return an invalid-state error. The message is literal text with optional `${expression}` fields, evaluated against the stopped thread's registers and bounded target memory; fields default to hexadecimal with a `0x` prefix, while `:d` requests decimal and `:x` requests hexadecimal. `$$` emits a literal dollar sign. For example, `rax=${rax} low=${rax & 0xff:d} byte=${mem8(rbx):x}` reports register and memory values. Messages and expanded output are capped at 1,024 bytes, and each message can contain at most 64 fields. An empty message keeps the default address/ID text. These rules are project-backed when edited through the desktop with a verified image mapping. Conditions and logpoint fields are evaluated by the session after a breakpoint stop, so native Windows and RSP use the same policy. A false condition resumes the event; a true ordinary breakpoint stops; a true logpoint prints the configured text and resumes. Evaluation errors stop at the breakpoint with an error message. Ignore counts are applied before conditions.

The expression subset accepts register names (case-insensitive), decimal or `0x` hexadecimal unsigned 64-bit constants, parentheses, unary `!` and `~`, multiplication/division/remainder, addition/subtraction, left/right shifts, bitwise `&`, `^`, and `|`, comparisons `== != < <= > >=`, and boolean `&& ||`, with conventional precedence. Boolean operators short-circuit: a false left operand skips evaluation of `&&`'s right side, and a true left operand skips evaluation of `||`'s right side. Skipped expressions still require valid syntax and remain subject to character, nesting, and operand limits, but do not read registers or target memory and do not report runtime arithmetic errors. Arithmetic wraps modulo 2^64. Division and remainder by zero, malformed expressions, and shift counts of 64 or more are rejected when evaluated. Bitwise operators make flag and address masking available, for example `(eflags & 0x40) != 0` or `(rax & 0xff) == 0x7f`. Register values must be scalar, at most 64 bits, and have known byte order. `mem8(address)`, `mem16(address)`, `mem32(address)`, and `mem64(address)` read exactly that many bytes from the stopped target and interpret them in target byte order. These reads are bounded by the same 64-operand expression limit; a short or failed read surfaces an error and leaves the breakpoint stopped. Expressions are limited to 256 characters, 64 parsed operands, and 16 nested levels. Arbitrary dereference syntax, calls other than the four fixed-width memory readers, assignments, and side effects remain unsupported. Unknown registers, unavailable register snapshots, unsupported register widths/byte order, malformed syntax, and resource-limit errors fail closed by surfacing a stopping event with an error message; they never cause an automatic continue.

Logpoint and diagnostic text is aggregated to at most 4096 bytes per event. Events with more than 4096 matching breakpoint IDs stop with a diagnostic and skip automatic condition/logpoint processing, avoiding an unbounded scan. The plugin ABI retains its 256-byte event message field and therefore returns a marked, UTF-8-safe prefix when the core event message is longer.

Invalid persisted fields are rejected while loading a project. Invalid conditions encountered at runtime surface a stopping event with an error; they never cause automatic continue. Applying a project breakpoint restores its condition, logpoint message and ignore threshold, while runtime hit counts remain fresh.


## Desktop breakpoint columns
The desktop Debugger pane shows each owned breakpoint's enabled state, runtime hit count, configured ignore threshold, and condition/logpoint rule beside its address and kind. It refreshes the inventory after a target event so hit counts remain visible while debugging. The table does not include breakpoints created outside the HexLab session.

## One-shot software and hardware-execute breakpoints

`DebugSession::set_breakpoint_one_shot` enables a session-only one-shot policy
for owned software and hardware-execute breakpoints. A breakpoint remains armed
through ignored hits and false condition results. On the first hit that passes
both checks, HexLab disables the breakpoint before exposing the stop or
automatically continuing a logpoint. If the backend cannot disable it, the hit
remains a visible stop with a diagnostic and the one-shot policy remains armed
for a later retry. Data watchpoints are rejected because read/write hit
attribution and disable support vary by backend. The setting is not persisted
in project breakpoint records.

The desktop breakpoint rule controls expose a session-only one-shot checkbox and
inventory column for software and hardware-execute breakpoints. It is not saved
in project breakpoint settings; project conditions, logpoint settings, and
ignore counts continue to persist independently.

## Navigate to an owned code breakpoint

Select a row in the Debugger breakpoint inventory and choose **Go to** to move
the active project listing to that runtime breakpoint's mapped image address.
The action requires a stopped target and uses the same verified module mapping
as frame navigation. It supports software and hardware-execute breakpoints;
data watchpoints have no corresponding code location and are rejected. Missing,
ambiguous, changed, or non-executable image mappings leave the listing where it
is and report why navigation is unavailable. This action does not resume the
target or change the breakpoint.

## Enable or disable an owned breakpoint

Select a breakpoint row and choose **Toggle enabled** to change its live session
state. The inventory refreshes to show the new state. When a verified mapping to
the active project image is available, the enabled state and the breakpoint's
persisted rule are also submitted to the project. If no mapping is available,
the change remains session-only. Backend errors, including unsupported toggle
operations or an invalid target state, leave the displayed inventory unchanged.
The one-shot policy remains session-only.

## Set a breakpoint at an inspected frame

Choose a frame in the stack selector and select **Set breakpoint** to install a
software breakpoint at that frame's runtime PC. The action requires fresh frame
inspection for the current stopped event. It reuses the breakpoint rule fields
(condition, logpoint, ignore count, and one-shot) and the normal project mapping
and persistence path. The address, kind, and size entry controls are restored
after the attempt. Backend failures are reported by the regular breakpoint
workflow; the action does not resume the target.

## Filter the breakpoint inventory

The breakpoint filter matches text in the ID, runtime address, kind, enabled
state, hit count, ignore threshold, condition/logpoint rule, and one-shot state.
It is ASCII case-insensitive and reports visible and total owned breakpoints.
Remove, save-rule, toggle, and Go to actions resolve the selected visible row
back to its session-owned breakpoint. Clearing the filter reveals all current
session breakpoints again; the filter is not saved in the project.

In the breakpoint address field, press **Enter** to add the breakpoint using the
selected kind, size, and current rule settings. It follows the same validation,
backend support checks, and project persistence behavior as the **Add** button.

Use the adjacent ordering menu to view breakpoints in creation order, ascending
runtime address, descending hit count, or descending ignore threshold. Ties in
metric-based orders use breakpoint ID. Sorting applies before filtering, retains
the selected breakpoint when it remains visible, and is local to the pane.
