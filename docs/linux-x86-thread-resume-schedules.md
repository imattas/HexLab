# Linux x86 thread resume schedules

The Linux x86 ptrace backend accepts a resume schedule with several
`continue_execution` actions when a stop event is pending. Every listed thread
must be owned by the session and stopped, thread IDs must be unique, and the
schedule must include the thread that owns the event. Omitted threads and
threads listed with `stop` remain stopped. A schedule may contain several
continues and at most one single-step. A non-owner single-step requires an
explicit `stop` action for the event owner; an owner step may run alongside
selected continues.

For a multi-thread continue, the backend resumes selected peers first and the
event owner last. If a `PTRACE_CONT` fails partway through, it interrupts the
threads already resumed and waits for their stop statuses before returning the
original failure. Real signal or clone stops that race with rollback are kept
as deferred events. If rollback cannot re-establish the stopped state, the
session reports both errors and blocks subsequent resume operations until it
recovers the suspension.

When a multi-thread schedule continues the owner of a software-breakpoint
stop, the backend first executes the displaced instruction with all peers
stopped, rearms the breakpoint, then resumes the selected threads with their
requested signals. The internal step is not surfaced as a user step event;
the backend keeps waiting for the next real stop and returns that event after
stopping the process threads. An owner single-step schedule at the breakpoint
may also select peer continuations. The owner executes the displaced
instruction alone; after rearming the trap byte, selected peers resume with
their requested signal dispositions. The backend stops them and preserves any
racing signal, clone, or exit status before returning the owner's single-step
event, leaving peer events queued for later delivery. If a peer resume fails,
already resumed peers are stopped again, the owner still receives its
single-step event with the peer-resume failure attached, and recovery state is
retained. If rollback cannot stop every resumed peer, later resumes remain
blocked until recovery succeeds. If an earlier schedule already has a
single-step in flight, another schedule may continue other stopped threads,
but any new single-step action is rejected until the outstanding step produces
its event. This feature does not make multiple ptrace operations atomic.

Each scheduled action can choose a signal disposition. If the thread owns a
signal-delivery stop, omitting the choice preserves and redelivers that signal;
`not_handled` explicitly requests the same behavior and `handled` suppresses it.
This works for both the event owner and a signal already queued for a stopped
thread. A `stop` action keeps a pending signal with that thread for a later
schedule. Suppression is retained even if the stop event is surfaced later.
Process-wide continue also delivers queued signals for stopped peers. The
backend does not reinject ptrace interrupt stops or debugger-owned software,
hardware, and single-step traps. A SIGTRAP whose provenance cannot be read is
conservatively suppressed.

If a multi-thread resume fails after a peer has already restarted with a
signal, stopping that peer cannot undo signal-handler execution. The consumed
signal is removed from the queued state immediately after its successful
`PTRACE_CONT`, preventing a retry from delivering it twice. The still-pending
event owner remains available for retry.
