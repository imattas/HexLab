# Python stack analysis

The embedded `hexlab` API exposes the stack-frame facts already recovered for
each function. The project must have current analysis; `stack_frame()` accepts
an address in a uniquely owned function and returns `None` when that function
has no stack record. Ambiguous shared code raises `hexlab.Error`, so callers can
inspect `function_owners()` and choose a function entry.

```python
frame = project.stack_frame(hexlab.Address(0, 0x140001000))
if frame is not None:
    print(frame.maximum_stack_allocation_bytes, frame.complete)
    for index, slot in enumerate(project.iter_stack_slots(frame.entry)):
        print(slot.offset_from_entry_sp, slot.width, slot.read, slot.written)
        for access in project.iter_stack_slot_accesses(frame.entry, index):
            print(access.instruction, access.read, access.written, access.address_taken)
```

Offsets are relative to the stack pointer at function entry. A missing maximum
allocation means the analysis could not prove a single extent across reachable
paths; `complete` reports whether the collected frame facts are complete.
Slot and instruction-site queries use bounded pages. Slot access sites retain
read, write, and address-taken flags when available from the current derived
analysis. Re-run `project.analyze()` after edits that invalidate analysis, and
fetch page sequences again after reanalysis because slot ordering is derived
data rather than a durable database identity.

`hexlab_python libs/automation/examples/inspect_stack.py project.hxproj` prints
all recovered frames. Add a space and address to limit output to one function.
