# Guarded memory patch batches

`DebugSession::apply_memory_patches()` applies related, discontiguous edits as
one recoverable workflow on Windows native, Linux x86/x86-64 native, Linux
AArch64 native, and all-stop RSP sessions. `restore_memory_patches()` provides
guarded undo; undoing its successful report provides redo. Both APIs are
synchronous and require callers to serialize access to the session.

This extends the existing single-range `write_memory()` operation without
changing its behavior. It does not introduce processor-atomic transactions,
change page protections, allocate target memory, or continue debug events.

## Apply, inspect, undo

```cpp
using namespace hexlab::debugger;
MemoryPatch first{0x1000, {std::byte{0x90}, std::byte{0x90}},
    std::vector<std::byte>{std::byte{0x75}, std::byte{0x10}}};
MemoryPatch second{0x2000, {std::byte{0x01}}, std::nullopt};
std::vector<MemoryPatch> edits{first, second};

auto result = session.apply_memory_patches(edits, cancellation);
if (!result) {
    // Validation/preflight failed. No patch writes were attempted.
    show_error(result.error());
} else if (result.value().completion == MemoryPatchCompletion::applied) {
    // Retain this report to undo later, while attached to this process.
    auto undone = session.restore_memory_patches(result.value(), cancellation);
    // Inspect undone's Result and completion with the same rules.
} else {
    // The operation failed or was canceled after preflight. Inspect failure,
    // records, and rollback_failures before resuming the target.
    show_patch_report(result.value());
}
```

A batch contains 1 through 256 nonempty, non-overlapping ranges totaling at
most 1 MiB. Ranges may be adjacent and are processed in caller order. A range
must not wrap the address space. Optional expected bytes must have exactly
the replacement length. Invalid bounds and overlap fail before backend I/O.

Before writing, the session obtains a backend-specific whole-process stop
check and snapshots **all** ranges. Every supplied expected value must match.
Snapshot errors, short reads, cancellation during preflight, and mismatched
expected bytes return a `Result` error without patch writes. Immediately before
each write, the snapshot is checked again to detect intervening changes. Every
accepted write is read back and compared byte for byte.

The session requires an active pending stop token. Native Windows uses the
pending debug event's process suspension; Linux verifies every observed process
thread is traced and stopped. RSP requires all-stop mode and a pending stop.
For a multiprocess peer it explicitly selects the pending thread in the
session's inferior before memory access, because a prior register read could
have selected another inferior. Non-stop RSP is rejected even if currently
known threads appear stopped: that list does not prove all process threads are
quiescent. Custom backends must implement `Backend::prepare_memory_patch()`;
the default is unsupported.

## Failure and cancellation

After preflight, failures return a report rather than discard recovery data.
`failure` identifies the original failing range and error, including
`ErrorCode::canceled`. The session attempts to restore every range whose write
was attempted, in reverse order, including a write that returned an error
after possibly changing only part of its range. Each restoration is read back.
Recovery continues after individual restoration errors.

Cancellation is observed before preflight, between snapshots, before writes,
and after verification. It cannot interrupt an in-flight backend call. Once
recovery begins, the cancellation token does not suppress restoration work.
The existing backend/RSP operation timeout still applies to each call; the
batch has no separate overall deadline.

The report retains original and replacement bytes in caller order:

| Record state | Meaning |
| --- | --- |
| `untouched` | This operation did not attempt a write to the range. |
| `applied` | The replacement was read back successfully. |
| `restored` | Recovery read back the complete original snapshot. |
| `uncertain` | Recovery could not establish the complete original bytes. |

`rolled_back` means every attempted range was verified restored; it also
covers cancellation or conflict before the first write. `rollback_incomplete`
means at least one range remains uncertain, with its index and error in
`rollback_failures`. A backend restoration error followed by a successful
readback of the original bytes counts as restored. Recovery reports must be
inspected before continuing. The API does not automatically retry uncertain
ranges or block later explicit user actions. All snapshots remain available
for inspection and deliberate recovery through the ordinary memory API.

The original debug event remains pending with the same acknowledgement token
on success, failure, cancellation, and incomplete rollback.

## Undo and breakpoint boundaries

Undo accepts only a fully applied report from the same process attachment.
Reports carry an opaque weak identity that expires or changes when the session
is destroyed, launches or attaches a new process, reconnects, or switches remote
inferiors. Reusing an OS PID does not authorize undo against a new attachment.
Moving the session preserves its attachment identity. Continuing and stopping
the same attachment preserves the identity, but undo still requires every
current range to equal its recorded replacement. A conflict leaves all ranges
unchanged. Undo itself has the same preflight, verification, cancellation,
rollback, size, and breakpoint rules, and returns a new report for redo.

Owned software breakpoints, including disabled ones, must be removed before
patching overlapping bytes. Native reads expose physical traps whereas native
writes preserve the backend's saved original instruction; a trap snapshot is
therefore not a safe undo image. The overlap check uses the target instruction
width (four bytes for ARM/AArch64, one for x86), expands the ARM boundary by
two preceding bytes to protect Thumb instruction decoding, and conservatively
uses sixteen bytes for an unknown target architecture. Hardware breakpoints
and watchpoints do not add trap-byte overlap restrictions.

This workflow does not establish safety for memory-mapped I/O, other processes
writing shared mappings, device/DMA writes, or target code that changes the
same bytes between stops. Use ordinary RAM ranges whose writes can be reversed.
The optional preconditions and repeated readback detect changes; they cannot
make remote transport failures or externally modified memory atomic.
