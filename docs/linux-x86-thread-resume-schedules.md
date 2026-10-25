# Linux x86 thread resume schedules

The Linux x86 ptrace backend accepts a resume schedule with several
`continue_execution` actions when a stop event is pending. Every listed thread
must be owned by the session and stopped, thread IDs must be unique, and the
schedule must include the thread that owns the event. Omitted threads and
threads listed with `stop` remain stopped. Single-step actions can be combined
with `stop` actions only when exactly one thread is runnable.

For a multi-thread continue, the backend resumes selected peers first and the
event owner last. If a `PTRACE_CONT` fails partway through, it interrupts the
threads already resumed and waits for their stop statuses before returning the
original failure. Real signal or clone stops that race with rollback are kept
as deferred events. If rollback cannot re-establish the stopped state, the
session reports both errors and blocks subsequent resume operations until it
recovers the suspension.

Multi-thread schedules remain unsupported when the pending event owns a
software breakpoint, because the backend must displace and single-step that
instruction before safely resuming the owner. A multi-thread schedule also
cannot contain a single-step action. These checks fail before any thread is
resumed. This feature does not make multiple ptrace operations atomic; the
backend uses stop-and-rollback to contain partial failure.
