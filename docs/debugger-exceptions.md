# Native debugger exceptions

`DebugEvent::code` carries the operating-system exception code. Native
backends can also set `DebugEvent::first_chance` when the platform exposes
that distinction. Win32 reports the `DEBUG_EVENT` first-chance bit for every
exception event; other backends leave the optional value empty when they do
not provide equivalent metadata.

The caller chooses how Win32 delivers an exception when acknowledging its
event. `ContinueStatus::handled` consumes it as `DBG_CONTINUE`;
`ContinueStatus::not_handled` passes it to the target's exception dispatch as
`DBG_EXCEPTION_NOT_HANDLED`. The child-process integration test raises a
continuable user exception, forwards its first-chance event, and verifies that
the target's vectored exception handler resumes execution. Software `INT3`
breakpoints use the same exception event path, with the breakpoint address and
first-chance state exposed to the caller.
