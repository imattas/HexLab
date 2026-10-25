# RSP non-stop event and resume semantics

Status: implemented in the remote client/backend; runtime interoperability remains unverified here.

## Scope

The remote debugger may negotiate GDB Remote Serial Protocol non-stop mode when
the peer advertises `QNonStop+`. Preserve exact event-thread ownership through
continue and single-step operations, and use the packet-based interrupt command
required while RSP target resumptions are asynchronous. Keep all-stop behavior
unchanged.

## Behavior

- `continue_execution(sequence)` resumes the exact thread represented by the
  pending non-stop stop event with a thread-qualified `vCont;c` action.
- `continue_thread_execution(sequence, thread)` accepts only that pending
  event's owning thread in non-stop mode. It must not clear the event and resume
  a different thread.
- Single-step remains thread-qualified to the stop owner.
- Non-stop interruption sends a framed `vCtrlC` packet and requires an `OK`
  response. All-stop interruption continues to send raw byte `0x03`.
- Stop notifications remain queued and bounded by the RSP client, and `vStopped`
  drains their ordered reply sequence when the session next requests an event.
- A non-stop `vCont` resume consumes its ordinary `OK` packet reply before
  returning. Stop notifications interleaved before that reply are queued. This
  exchange works both with packet ACKs enabled and after no-ACK negotiation.
- If non-stop is not advertised or receives the protocol's unsupported reply,
  the backend uses all-stop mode. Other negotiation errors fail connection.

## Boundaries

`DebugSession` represents a single pending event sequence. The client therefore
surfaces multiple non-stop notifications serially, and the session does not
expose mixed per-thread `vCont` action sets. Runtime behavior against multiple
GDB stubs is still a platform interoperability requirement.
