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

The current remote RSP backend implements target termination. Native Windows,
Linux, and macOS backends report it as unsupported; the UI does not treat
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
