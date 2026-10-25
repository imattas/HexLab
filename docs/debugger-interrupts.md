# Requesting an asynchronous debugger stop

`DebugSession::request_interrupt` asks a running target to stop without
blocking the caller. The session remains `running` until `wait_event` consumes
the backend's stop notification. The resulting event is acknowledged through
the usual `continue_execution` or `single_step_execution` path. Requests are
valid only while running, and the session rejects a duplicate request until
the event arrives. A backend error leaves the session eligible for retry.

The Windows backend uses `DebugBreakProcess`; attached process handles include
the suspend/resume access right needed by that operation. Linux uses
`PTRACE_SEIZE` for attached and launched targets, interrupting each running
traced thread. Linux launch holds the child behind a socketpair until the tracer
has seized it and enabled exec/clone notifications, so a child cannot run ahead
of the initial exec stop or miss the interrupt capability. A process-wide request
can produce one stop event per running thread; acknowledge each reported
sequence normally. The RSP backend sends
the protocol's out-of-band Ctrl-C byte and later maps the peer's stop reply to
the normal debug event stream. A target or stub must support the applicable
platform operation; an interrupt request is not proof that the target has
stopped until an event is received.

`debugger` tests verify session state and duplicate/pending-event guards.
`debugger_remote` verifies the raw Ctrl-C wire byte and exercises a complete
remote-session resume, interrupt, asynchronous stop, and event transition.
On Windows, the native integration test launches a looping target, requests an
interrupt while running, receives the resulting breakpoint event, and detaches
before terminating the fixture.
