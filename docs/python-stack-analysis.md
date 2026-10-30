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
        print(slot.offset_from_entry_sp, slot.width, slot.read, slot.written,
              slot.incoming_argument, slot.outgoing_call_argument_count)
        print(slot.incoming_argument_abi)
        for argument in project.iter_stack_slot_call_arguments(frame.entry, index):
            print("argument source/call", argument.source_kind, argument.source_instruction,
                  argument.call_instruction)
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

`StackSlotInfo.incoming_argument` identifies either an x86-32 near-call incoming
argument location (entry-SP offsets `+4` and above; `+0` is the return address)
or an AArch64 AAPCS64 entry-SP offset `+0` or above that is read through a
tracked stack base. AArch64 write-only slots remain unclassified to separate
incoming reads from possible caller-side outgoing stores.
Read slots at x86-64 entry-SP offsets `+8` and above are classified as SysV
AMD64 incoming stack arguments; offsets `+40` and above are classified as
Windows x64 incoming arguments, excluding its return address and 32-byte shadow
space. `incoming_argument_abi` reports `x86-32-near-call`, `aapcs64`,
`sysv-x86-64`, `windows-x64`, or `mips-n64`; it is `None` when no supported ABI evidence
exists. The x86-64 default comes from image format: PE selects Windows x64,
ELF and Mach-O select SysV AMD64. ELF64 MIPS with no N32 marker or conflicting
ABI selector selects MIPS N64: reads from tracked entry-SP slots at `+0` and
above are marked `mips-n64` overflow arguments after the eight 64-bit argument
slots. This requires generic SysV/Linux ELF OSABI metadata. Raw/unknown formats
and other MIPS ABI selectors remain unclassified.
This is an image-level default; per-function convention overrides such as
`ms_abi` in ELF or `sysv_abi` in PE are not applied because function-level ABI
metadata is not passed to stack derivation.
`outgoing_call_argument_count` is the number of retained outgoing stack-slot
source/call pairs. Fetch those rows with `stack_slot_call_arguments()` or
`iter_stack_slot_call_arguments()`; each `StackSlotCallArgumentInfo` contains
`source_instruction`, `source_kind`, and `call_instruction`. The legacy
`push_instruction` field aliases the source address. x86 attribution is limited
to contiguous decoded `PUSH` instructions immediately before a call followed
by an immediate `ADD ESP,N` or `ADD RSP,N` matching the pushed byte total.
x86-64 requires a PE/ELF/Mach-O-derived Windows/SysV default ABI. AArch64
records direct write-only SP-relative `STR`/`STRB`/`STRH`/`STP` slots before a
same-block direct `BL`; the slot source and BL addresses are retained. Candidate
stores are discarded across other memory traffic, SP changes, control-flow
boundaries, or indirect calls. Reserved x86 stack areas and stores into
preallocated x86 outgoing slots remain unclassified.

`hexlab_python libs/automation/examples/inspect_stack.py project.hxproj` prints
all recovered frames. Add a space and address to limit output to one function.
