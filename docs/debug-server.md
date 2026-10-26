# HexLab GDB Remote Serial Protocol server

`hexlab_debug_server` is a separate C++ tool that exposes the local native
debugger session through a bounded GDB Remote Serial Protocol connection. It
uses the same `DebugSession` and backend DLLs as the desktop and native SDK.
It accepts one client and one target for the duration of a server run.

```text
hexlab_debug_server --launch path/to/program [-- arg1 arg2 ...]
hexlab_debug_server --attach 12345 [--bind 127.0.0.1] [--port 1234]
```

The default listener is `127.0.0.1:1234`. GDB clients can connect with
`target remote 127.0.0.1:1234`. The server starts or attaches the target after a
client connects, waits for the initial debug stop, and then serves the RSP
session. `--working-dir` selects a launched target's working directory.

The listener can control the target process. Keep it on loopback unless the
operator intentionally provides an explicit `--bind ADDRESS` for an isolated
trusted network; RSP has no authentication or encryption. A firewall or secure
tunnel is needed when connecting from another machine.

The bounded protocol subset covers packet checksum/escaping and ACK retry,
`qSupported`, no-ACK negotiation, target XML register descriptions, general
and per-register reads/writes, memory reads/writes through both binary `X` and
hexadecimal `M` packets, thread selection and enumeration, continue,
single-step, interrupt, software breakpoints, stop replies, and detach. RSP
packet payloads are capped at 16 KiB; the server advertises an 8 KiB packet
payload limit so worst-case escaped binary writes stay within that cap. Memory
operations are limited to 4 KiB. Unsupported packets receive an empty response.
When the active backend can enumerate modules, the server also advertises
`qXfer:libraries:read` and returns a bounded `library-list` XML snapshot with
each module's path and base address. The snapshot is refreshed at offset zero
and held stable across continuation chunks. Paths are XML-escaped, the module
count is capped at 4,096, and the total annex is capped at 1 MiB; the RSP client
decodes predefined and numeric XML entities in library attributes. Backends
without module enumeration omit this feature from `qSupported`.
The server supports `Z1` hardware execute breakpoints on Windows x86/x64 and
Linux x86-64 targets, and advertises `hwbreak+` only for those combinations.
It also routes `Z2`/`Z3`/`Z4` write/read/access watchpoints through the native
backend; unsupported target/backend combinations receive an empty response.
Native Windows ARM64 builds also route `Z1`–`Z4`. ARM64 `Z0` and `Z1` packets
require instruction kind `4` and four-byte alignment; the server translates
`Z1` to the shared backend's one-instruction-slot size. Data watchpoint sizes
remain byte lengths. ARM64 does not advertise `hwbreak+`: its backend can
program debug registers but does not yet identify the hardware slot that hit.
Hardware support is gated by both the server host build and target architecture.
Empty, overflowing, wrong-width instruction and out-of-range x86 requests are
rejected before installation; native backends validate data alignment and slots.
Repeated insertions and removals of the same address, kind, and size are
idempotent.
Execution control uses the pending `DebugSession` event sequence. A successful
resume consumes that event once and waits for the next stop; the `T` reply's
`thread` field and `qC` identify the thread that produced that stop, independently
of the register context selected by `Hg`.

On Linux x86/x64, a global continue resumes every traced thread held at a
debugger stop, including the peer threads acquired during attach. Real signal,
clone, and exit events collected while stopping peers remain deferred owned
events; those threads stay stopped until their events are presented and
acknowledged. The backend stops peers before publishing a stop and uses a
bounded two-second wait for internal `PTRACE_INTERRUPT` requests.
An active user step is collected before deferred peer events, so its completion
or exceptional stop is reported before the queued events and its instruction
step cannot be replaced by a later global continue.

Continuing an owned `INT3` first holds all peers stopped, restores and steps
the displaced instruction, and reinstalls the trap before resuming the process.
A confirmed internal trace trap completes the original continue without being
reported as a user single-step. Owned hardware watchpoint hits take precedence
even when Linux reports a trace trap for the displaced instruction; the stop
retains its breakpoint IDs and configured watchpoint address. Unreadable DR6
status prevents automatic continuation. Other signals or events remain visible. If
resuming several threads fails partway through, the backend interrupts the
threads released by that attempt and retains the pending event. Failed peer
suspension or breakpoint/PC restoration blocks further execution until recovery
succeeds; the failure is returned or attached to the owned stop event. Linux
ptrace operations cannot atomically roll back instructions that already ran
before a peer resume failure.

The server advertises `vContSupported+`; `vCont?` reports `vCont;c;t;s` on native
target/backend combinations that implement instruction stepping, and `vCont;c;t`
otherwise (including Windows ARM32). Backends supporting scheduled signal
disposition also advertise `C` and, when stepping is supported, `S`. Supported
execution forms are:

| Packet | Behavior |
| --- | --- |
| `vCont;c`, `vCont;c:-1` | Continue the session through `DebugSession::continue_execution`; do not restrict execution to one thread. |
| `vCont;s:TID` | Step the exact hexadecimal thread ID through the shared scheduling API; support for a non-event thread depends on the native backend. |
| `vCont;s:0` | Choose the current stop's thread for one instruction. |
| `vCont;s`, `vCont;s:-1` | Request a step for every live thread. Current native backends accept this only for a single-thread target; they reject general multi-thread stepping. |
| `vCont;c:TID` | Resume only the selected thread, keeping unmatched threads stopped. Linux supports non-event-thread selection within its bounded subset; Windows requires the event owner to run. |
| `vCont;c:0` | Select the event thread as the server's choice for `0` (any thread), then use exact thread continuation or the one-live-thread equivalent. |
| `vCont;t:TID;c` | Keep the exact live thread stopped and continue its peers, subject to native scheduling restrictions. `t:0` selects the event owner. |
| `vCont;c:TID;t`, `vCont;c:TID;t:-1` | Continue only the exact live thread and explicitly keep the remaining threads stopped. |
| `vCont;t`, `vCont;t:-1`, `vCont;t:TID` | A stop-only result returns `E01` while retaining the owned event; this all-stop server requires at least one thread to continue or step. |
| `Hc0`, `Hc-1`, `HcTID` | Set the execution selection for legacy `c`/`s` packets. Positive IDs must identify a live thread. This selection does not affect `vCont` or register access. |
| `c[ADDR]` | Continue the session with `Hc0` or `Hc-1`; a positive `HcTID` selection resumes only that thread when it owns the stop and the backend supports exact thread continuation. |
| `s[ADDR]` | Step the stop thread with `Hc0` or a matching positive `HcTID`. With `Hc-1`, require that it is the only live thread. |

The initial execution selection is `Hc0`. It persists across stops until the
client changes it; a positive selection that differs from the next stop thread
cannot silently redirect a step. Legacy `ADDR` values change the stop thread's
instruction pointer, even when `Hg` selects a different register context. Values
that do not fit that instruction pointer's width are rejected. Execution
selection and syntax are validated before any instruction-pointer write.

`vCont` accepts up to 4,096 actions within the packet-size bound. The complete
list and all selectors are validated before changing target state. The first
matching action applies to each live thread, and unmatched threads stay stopped.
Continuing every live thread retains the ordinary process-wide continuation
path. Every other result becomes one complete `DebugSession::resume_threads`
schedule, including explicit `t` actions and stop actions for unmatched live
threads. The pending event owner must be represented. Backends validate the whole plan and
reject unsupported combinations without replacing them with global continue.
Linux x86/x64 and AArch64 accept one selected thread continuing or stepping, or
a continue-only subset; breakpoint step-over and deferred-event restrictions
still apply. Windows accepts event-thread stepping or a continue-only subset
that includes the event owner. Darwin accepts only a proven single-thread
target. See [Native thread schedules](../libs/debugger/docs/thread-resume-schedules.md)
for exact restrictions and failure behavior.

For example, with A owning the stop and C remaining stopped,
`vCont;c:A;c:B` continues A and B on supported Linux and Windows targets;
`vCont;c:A` continues A alone; `vCont;s:B` steps B on supported Linux stops
while holding A, and is rejected on Windows; `vCont;s:A;s:A` steps A once.
`vCont;s:A;c` combines an event-owner step with peer continuations on supported
Linux stops and is rejected on Windows. Shadowed actions do not override
earlier matches: `vCont;t:A;c` keeps A stopped, while `vCont;c;t:A`
continues every thread because the first action already matches A. Explicit
stop actions retain any pending native signal for the held event owner.
They do not request a new stop notification for already stopped threads.
A failed or empty thread snapshot,
unknown or malformed selector, multiprocess ID,
unsupported signal-delivery action, range step, or stop-only result returns
`E01` without consuming the event. IDs are bounded to 64-bit hexadecimal values; only literal
`0` and `-1` are special selectors. Rejected requests never fall back to a
global continue unless it is equivalent for a single-live-thread target.

The `t` integration uses the existing all-stop event and native schedule API.
It does not enable `QNonStop` or accept execution packets while a run is in
progress. The GDB protocol requires zero-signal stop replies when `t` actually
interrupts a running thread in non-stop mode; this server does not implement
that operation ([GDB packet specification](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html)).

Target restart/kill, multiprocess sessions, non-stop mode and simultaneous native
multi-thread steps remain unsupported. Server-side signal control is limited to suppressing or redelivering
the pending event owner's signal on backends with scheduled disposition support.
General thread selection is honored for register
access; legacy `s` still selects the event thread, while `vCont` can select
another thread where the native scheduling backend supports it. The selector meanings follow the
[GDB RSP packet specification](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html).

When HexLab connects as an RSP client, it preserves the exact wire thread ID
in a qualified step, including a multiprocess ID from another server. A trap
from a different thread is reported as an exception rather than completion of
that step. If a stop reply supplies no thread ID, the client uses legacy `s`
with the peer's current selection instead of sending an all-thread `vCont;s`.
Target architecture and register availability depend on the native debugger
backend on the host.

The thread-schedule integration received source review only; no builds, tests
or live target/stub interaction were run for this increment. Follow up with
serial `hexlab_debugger` and `hexlab_debug_server` compilation. Linux x86,
AArch64, Darwin and Windows ARM64 paths need their respective native builds and
runtime validation; a Windows x64 compile does not validate those paths.
