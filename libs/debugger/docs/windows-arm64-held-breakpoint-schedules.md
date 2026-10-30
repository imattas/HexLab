# Windows ARM64 held execute-breakpoint schedules

A filtered continue may keep the event-owning thread stopped while selected
peer threads run, including when that event is an ARM64 hardware execute
breakpoint. The event owner is suspended before `ContinueDebugEvent`; the
execute breakpoint remains installed and the owner remains at its stopped
instruction. When that thread is later resumed, the breakpoint can report a
new event before the instruction executes, where the user can step over it.

When the event owner is selected to run, a schedule may also single-step it
over the execute breakpoint while selected peers continue. The backend
temporarily disables the owned execute slot on the owner, enables architectural
single-step, and keeps the owner in the selected resume set. Only omitted
threads receive debugger-owned suspend counts. On the next debug event, those
counts are released while Windows has frozen the process; the resulting event
is then surfaced normally. If setup or event continuation fails, the owner
context, breakpoint slot and acquired suspension counts are restored or retained
for cleanup retry before the event is returned.

The mixed form applies only to a handled ARM64 hardware execute-breakpoint
event, with exactly one step action on its event owner. Other mixed step and
continue schedules remain unsupported. To keep selected threads running
together, include each in the schedule as a continue action; omitted peers are
held until the next debug event.

This schedule relies on Windows freezing the process while a debug event is
pending and on the backend's suspend-count ownership for unselected threads.
See Microsoft's [debugging-event suspension rules](https://learn.microsoft.com/windows/win32/debug/debugging-events)
and [`ContinueDebugEvent`](https://learn.microsoft.com/windows/win32/api/debugapi/nf-debugapi-continuedebugevent).
