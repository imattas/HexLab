# GDB Remote Serial Protocol packet handling

## Remote process enumeration and attach

When the stub advertises `qXfer:osdata:read`, HexLab reads the `processes`
annex and exposes the validated PID/command rows in the desktop process list.
After connecting, select a listed process and press **Attach** to attach the
existing RSP connection to that inferior. This uses `vAttach;PID` and requires
`multiprocess+` plus a successful `!` extended-remote request, since `vAttach`
is an extended-mode packet. In all-stop mode the returned `T`/`S` stop reply
must identify a concrete `pPID.TID` in the requested process. In non-stop mode,
the server may return `OK`; the process becomes selected and later stop
notifications arrive through the ordinary event path. A missing or foreign
thread identity in an all-stop reply, unsupported packet, or process absent
from the current process list fails closed.

The session's process identity changes only after a valid attach reply or a
successful PID-qualified selection of an already attached inferior. Thread
enumeration filters to that PID, and thread tokens retain their complete
`pPID.TID` wire identity. Register reads/writes and thread-qualified resume
operations select or validate those tokens against the selected inferior.
For each PID, the RSP backend retains whether it has attached that inferior,
its cached stop reply, and its thread run states. Switching saves the selected
inferior's state first. A PID already attached on this connection is selected
with `HgpPID.-1` and its cached stop/thread state is restored; a PID not yet
attached is selected with `vAttach;PID`. Thread run-state snapshots remain
keyed by their full `pPID.TID` IDs, so a stop or detach in one inferior does
not rewrite another inferior's thread state. A cached inferior is reusable
only while the stub accepts PID-qualified general-thread selection. If it
does not, HexLab returns the server's explicit unsupported/error result and
does not silently issue a second attach. Process discovery and attach are unavailable when
the stub omits the `osdata` annex or multiprocess support; the initial inferior
from a normal single-process connection remains supported as before.

`DebugSession::detach_remote_process(pid)` detaches a different listed process
on the same multiprocess connection with `D;pid`. The currently selected
process remains attached, its pending stop and breakpoints remain valid, and
the session can continue using it. Thread tokens and run-state entries for the
detached PID are discarded so callers cannot reuse stale identities; already
queued stop notifications with that PID are discarded as well. The API
rejects the selected PID; use selected-process detach or ordinary session
`detach()` to end the active debug session. This operation requires process enumeration so the PID is
checked against the remote process list before sending the detach request.
Explicit per-PID detach sends `D;pid`; if the server returns an empty response,
HexLab reports `unsupported` and does not fall back to `D`, which would detach
the entire connection. PID-scoped termination similarly uses `vKill;pid`; an
unsupported response is returned without sending global `k`. After successful
PID-scoped termination, only that inferior's threads are marked exited and the
RSP connection remains available for enumeration or another attach.

For `detach()` on a multiprocess extended-remote connection, HexLab first
attempts `D;pid` for the selected inferior. If accepted and another process is
listed, it attaches the first remaining PID and keeps the RSP connection and
`DebugSession` active on that process. Breakpoints must be removed before this
selection change. The PID-qualified form follows the GDB packet definition
([GDB RSP detach packet](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html)).

If no other process is listed or process enumeration is unavailable, detach
ends the session as before. If the server rejects `D;pid`, HexLab tries plain
`D` to end the whole remote session and records a fallback explanation in
`DebugSession::last_diagnostic()`; remaining inferiors are not preserved.
Other protocol errors are returned without fallback. If selected-process
detach succeeds but attaching the next process fails, HexLab closes the
connection and returns that attach error. Single-process connections continue
to use `D`.

The desktop process row selects the PID used by **Attach**. After a remote
process is attached, refreshing the list selects the active process by default.
**Detach secondary** is enabled only when the selected row is a different,
currently listed PID in a live remote session; it never detaches the active
process. The backend revalidates the PID against a fresh process list before
sending `D;pid`. If the remote list changed, the error is reported and the UI
refreshes while preserving the active session.

HexLab's RSP client validates packet framing and checksums, reverses byte escaping, and expands the standard response run-length encoding before command-specific parsing. For example, a response payload `0* ` expands to `0000`: the byte after `*` encodes three additional copies using its ASCII value minus 29. A literal asterisk must be escaped by the peer and remains literal after unescaping.

Run-length expansion is bounded independently of the wire packet size. `rsp::Client` applies its configured maximum packet size to the decoded response as well as the received frame, so a compact packet cannot expand into unbounded memory. Standalone `decode_packet` calls default to a 1 MiB decoded-payload limit and may pass a smaller limit. Invalid/truncated run-length sequences return `malformed`; payload expansion beyond the limit returns `resource_limit`.

This covers response-data RLE defined by GDB. Packet encoding intentionally continues to send ordinary escaped payloads; it does not attempt to compress requests. Cisco-specific legacy RLE and interoperability with a live remote stub are not covered by this feature.

At connection setup, the remote backend uses the stub's `vContSupported` feature
and queries `vCont?` before choosing continue and step packet forms. It sends
`vCont;c` only when the `c` action is advertised, with a legacy `c` fallback
otherwise. The `vCont?` reply lists supported action kinds; the packet grammar
allows an action to name a thread even when the reply lists only the unqualified
kind. Thus an advertised `s` permits `vCont;s:<thread>` for a stop that identifies
its thread. If the thread is unknown, HexLab uses legacy `s` with the peer's
current selection. A stop with a known thread is never
single-stepped through the all-thread `vCont;s` form or an ambiguous legacy
current-thread selection. Support for one `vCont` action is not treated as
support for every action.

Continue retains process-wide debugger semantics. Single-process connections
use `vCont;c` or legacy `c`. A peer that negotiates multiprocess support receives
`vCont;c:pPID.-1` for the process identified by the initial stop, so continuing
one session does not resume other inferiors. That path requires an advertised
`c` action and a current stop belonging to the same process; otherwise it
reports unsupported without sending a resume packet. Stepping likewise rejects
a missing or foreign process identity in multiprocess mode. The shared session
API also exposes `continue_thread_execution(sequence, thread)`. This operation
requires an opaque thread token obtained from the event or thread listing and
an advertised `c` action, then sends exactly one `vCont;c:<wire-thread-id>`
action. The full `pPID.TID` identity is retained in the token mapping and checked
against the session process before sending. It never falls back to global
continue. `resume_threads(sequence, actions)` submits one complete mixed schedule: each
action names an exact session thread and chooses continue (`c`), single-step
(`s`), or remain stopped (`t`). The backend requires the corresponding action
to be advertised by `vCont?`, rejects duplicate/unknown/foreign thread tokens,
and sends the whole schedule in one `vCont;...` packet. The thread owning the
pending stop must appear in the schedule. If validation or transmission fails,
the pending event remains available for retry. The API tracks expected step
completions by thread, so an intervening stop from another thread does not
consume the step expectation. Session state remains a coarse running/stopped
summary; use `thread_run_states()` for the backend's known per-thread state.
Native backends implement bounded exact schedules described in
[Native thread schedules](../libs/debugger/docs/thread-resume-schedules.md).
A schedule is validated as one operation; it does not promise processor-atomic
execution or rollback of instructions already executed after an OS resume.
Multiprocess `W`/`X` exits retain their `process` field and only transition the
session to exited when that field identifies its process. Missing or foreign
exit identity reports unsupported rather than marking another process exited.

The initial `ProcessInfo` uses the process component of `pPID.TID` when present.
Stopped events retain that process component separately from the opaque local
thread token. Register selection requires a known token returned by a stop or
thread listing; an unknown token is rejected rather than interpreted as a raw
wire ID. Stop and enumeration IDs must name concrete positive threads, not the
`0`/`-1` selector forms.

When `qSupported` advertises `qXfer:osdata:read`, `DebugSession::processes()`
reads the standard `processes` annex and returns its decimal PID values with
the optional `command` column as each process name. The bounded XML reader
accepts the standard `osdata.dtd` declaration and predefined/numeric XML
entities, rejects malformed or duplicate PIDs, and caps the document at 1 MiB
and the process list at 4,096 entries. Missing command columns fall back to
`process <pid>`. Stubs without this feature continue to report process
enumeration as unsupported; listing does not attach to or change the selected
remote process.

Remote hardware execute and data watchpoints retain owned IDs, kind and size.
The common `DebugSession::set_breakpoint_enabled` operation sends `z` to
disable or `Z` to re-enable the exact owned tuple, preserving its local ID.
Duplicate wire tuples (including hardware/execute aliases) report conflict
before sending another `Z` packet, preventing one local owner from removing a
trap still claimed by another. Empty or overflowing ranges are rejected.
In multiprocess mode, breakpoint changes require a current stopped thread in
the session process and explicitly select it before sending `Z`/`z`, since
register inspection may have selected another inferior. Foreign-process stop
reasons never acquire this session's breakpoint IDs.
For targets identified as AArch64 by target XML, execute size `1` in the shared
API becomes instruction kind `4` in `Z1`/`z1`; software `Z0`/`z0` likewise uses
four bytes. Watchpoint sizes remain byte lengths. Stop replies with a watchpoint
reason and an address within an enabled owned range populate `breakpoint_ids`.
Execute/software hits require an explicit matching reason and `pc` address;
generic traps or replies without an address do not guess ownership.

Memory writes use the binary `X` packet first and fall back to hexadecimal `M`
when a peer replies with the protocol's empty unsupported-packet response. Both
forms are split into bounded chunks using the peer's advertised `PacketSize`;
binary chunk sizing reserves worst-case RSP escaping expansion, so arbitrary
bytes cannot exceed the negotiated wire payload limit.

When `qSupported` advertises `QNonStop+`, the remote backend requests `QNonStop:1`; peers that do not support the request remain in all-stop mode. In non-stop mode, `%Stop:` notifications use the normal RSP checksum and escaping rules and carry no `+`/`-` acknowledgement byte. HexLab acknowledges each stop through the `vStopped` sequence, including additional synchronous stop replies and the terminating `OK`. Stop notifications that arrive while another command response is being read are retained for the next `wait_stop_reply` call, and the backend maps them through the regular `DebugSession` event path. The pending queue is bounded to 4,096 stop replies and to the configured aggregate packet-byte budget; exceeding either bound returns `resource_limit` from the in-flight operation. The session exposes one stop event at a time, while the remote target may continue other threads; unqualified continue resumes the exact stopped thread in non-stop mode. `DebugSession::thread_run_states()` provides a token-keyed snapshot with `unknown`, `running`, `stopped`, and `exited` states for every RSP thread known to the session. Thread-list XML seeds or refreshes the snapshot when it includes state; stop notifications update the owning thread; thread-created/thread-exited reasons update lifecycle state; and successful resume schedules update only the threads named by their actions. An all-stop notification marks all known threads stopped, while non-stop notifications change only their identified thread. `request_interrupt()` does not predict a stop: state changes only as stop notifications arrive. The snapshot retains known exited threads and may omit threads not yet observed or enumerated. When a legacy all-stop step has no identified thread, the backend marks active-thread states `unknown` rather than guessing which one ran. `SessionState` remains a coarse session summary, and the common API still acknowledges one stop event at a time, so simultaneous pending-event ownership is not modeled. A multiprocess target that reports no initial stop and therefore provides no process identity is rejected rather than assigned to an arbitrary process.

Notification packets are also consumed while the client waits for an ACK in
ACK mode, for both ordinary requests and resume packets. Valid stop notifications
are queued without acknowledging them, then the ACK wait continues. This avoids
discarding a stop that races with the packet ACK. A command response packet
received before its ACK is reported as a protocol error instead of silently
being consumed. Notification payloads retain the same queue-count and aggregate
byte limits.

## Target termination

`DebugSession::terminate()` is distinct from detach: it requests target process
termination and transitions the session to `exited` only after the backend
accepts the request. Native backends still report termination as unsupported
until they implement their platform-specific process control.

For a remote stub that advertised `multiprocess+`, HexLab uses `vKill;pid` with
the process component from the initial stopped thread ID (`pPID.TID`). It
requires an `OK` response and will not fall back to `k`, because `k` may kill
more than the selected process on multiprocess targets. After a successful
`vKill;pid`, the selected inferior's known threads are marked exited and the
multiprocess connection stays open so the caller can enumerate or attach to a
remaining inferior. If no process component was supplied, termination reports
unsupported rather than guessing.

For a single-process RSP connection, HexLab sends the `k` kill request. The
protocol defines no packet reply for `k`; successful transport write is treated
as request acceptance, and the connection is closed locally. Since remote stubs
may close the connection after receiving the request, HexLab does not wait for
an ACK or stop reply. This follows the packet's no-reply semantics in the
[GDB Remote Serial Protocol packet reference](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html).
