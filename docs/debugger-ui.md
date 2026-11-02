# Debugger window behavior

The debugger offers separate **Detach / Disconnect** and **Terminate target**
commands. Detach leaves the target process running. Terminate prompts with a
No-default warning before requesting permanent target termination.

Termination runs on a worker so a remote protocol round trip does not block the
wxWidgets event loop. The debugger panel disables its controls and stops event
polling while the request is in flight. On backend success, it clears the
pending event and inspection panes, displays `Target terminated.`, and refreshes
the state to `Exited`. On failure or unsupported behavior, it preserves the
current state and last-event display, reports the backend error in the output
log, and re-enables the panel. If the target remains running after a failed
request, event polling resumes.

The current remote RSP backend implements target termination. Native Windows
and Linux backends report it as unsupported; the UI does not treat
unsupported as detach or pretend the target exited.

Remote RSP connection and the first process enumeration run on the serialized
inspection worker. The panel shows `Connecting...` and disables its controls
while DNS lookup, TCP setup, protocol negotiation, and the initial listing are
in progress. A connection failure is reported in the debugger output and leaves
the panel available for another attempt. If connection succeeds but process
enumeration is unsupported or fails, the remote session remains active and the
process selector shows the listing error. Closing the debugger view before a
pending connection completes disconnects a successful late connection instead
of leaving an unowned remote session behind.

## Guarded memory patch batches

Open **Patch batch...** beside the Memory pane's existing **Write** button.
The modal editor provides address, optional expected bytes, and replacement
bytes in separate editable columns. Use **Add range** and **Remove row** for
1–256 non-overlapping ranges totaling at most 1 MiB. Addresses accept decimal
or `0x` hexadecimal; byte columns accept hex pairs. Leave expected bytes blank
to snapshot the current contents without a caller precondition.

Stop the target before **Apply batch**. The batch runs on the serialized
inspection worker; the dialog stays responsive, and the main window remains
unavailable until the editor closes. **Cancel operation** requests cooperative
cancellation, which waits for an in-flight backend call and does not interrupt
recovery. Closing during an operation requests cancellation and keeps the
editor open until completion. Event polling pauses during the batch.

The report distinguishes applied, verified rollback, and **ROLLBACK INCOMPLETE**.
It includes the original failure, recovery failures, each row's state, and full
before/replacement snapshots. Inspect uncertain ranges before explicitly
continuing the target. The editor never resumes the target automatically.

**Undo / redo last batch** restores a retained successful report through the
same guarded API. A successful undo becomes the next redo; a conflict fails
before writes. Incomplete recovery clears the undo candidate. Reports, editor
rows, and undo are attachment-scoped and cleared when the UI changes sessions.
Queued operations reject changed session/stop generations before execution;
late results cannot authorize undo against a different attachment. These
in-memory reports are not persisted across application restarts.

The ordinary single-range Write workflow is unchanged. Backend stop,
breakpoint, expected-byte, and recovery rules are described in
[Guarded memory patch batches](../libs/debugger/docs/memory-patch-batches.md).
