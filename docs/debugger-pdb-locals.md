# Live PDB locals in the debugger

For a PE image with a uniquely matched PDB, the debugger can display CodeView
locals and parameters from the bound PDB metadata. A value is evaluated only
when a CodeView defrange covers the selected frame's current PC and the PC is
outside that range's gap list. Locals nested in `S_BLOCK32` additionally require
the PC to lie in the nearest enclosing lexical block's half-open code range:
the start is included and the end is excluded. A full-procedure defrange does
not widen a nested local's lexical scope. Procedure-scope locals have no block
restriction and retain their existing defrange visibility throughout the
procedure. The table reads the selected frame's live registers and uses the
debugger memory reader for memory-backed locations.

Block extents bind through the identity-matched PDB's section ordinal and the
loaded PE section declarations. The complete range must fit the section, image,
address-space width, and one executable image segment, agree with the bound
procedure, and lie entirely inside that procedure. Overlapping section or
segment mappings, zero or invalid extents, and arithmetic overflow leave the
scope unresolved. Within a known containing procedure, such a local retains a
row with Location `unresolved`, its raw section/offset/size in Scope / origin,
and no evaluated value. A valid block outside the selected PC is omitted before
any register or memory evaluation. This filtering applies to the debugger locals
table; function-wide pseudocode local-name and type inference remains separate.

Currently evaluated locations include AMD64/x86 register values and ARM64
integer-register locations: CodeView W0-W30 are read as the low 32 bits of the
corresponding debugger X register, X0-X28 map to their full-width registers,
and FP/LR/SP map to x29/x30/SP. Values wider than the recorded CodeView
register width remain unavailable; zero registers are not treated as writable
storage. Frame-pointer-relative memory uses RBP/EBP or x29, and
register-relative memory uses the architecture's supported CodeView register
identifiers. `S_DEFRANGE_REGISTER_REL_INDIR`
follows CodeView's `*(Register + BasePointerOffset) + OffsetInUDT` recipe. A
whole local is read at the pointee only when both recorded member offsets are
zero. For a nonzero offset, the evaluator requires the local's type to be a
complete, non-union aggregate and requires `OffsetInUDT` to agree with the
recorded parent offset; it then resolves exactly one non-inherited data member
and reads that member's declared type size. Spilled register-relative members
use the same complete parent layout and unique-member checks; the selected
register plus signed displacement supplies the member address, and indirect
spilled members additionally require both nonnegative offsets to identify the
same member. Direct `S_DEFRANGE_REGISTER_REL` records have no `OffsetInUDT`
operand, so the evaluator rejects a nonzero in-memory value for that field
instead of applying it as an invented address displacement. The parent field
list is capped at 4096 entries.

`S_DEFRANGE_SUBFIELD_REGISTER` also resolves the parent aggregate's expanded
CodeView field list and reads the exact field type size from the register when
exactly one non-inherited data field begins at the recorded parent offset. In
all three paths, field and sibling data-member extents must be known, fit
within the parent, and not overlap. Missing field lists, unions, inherited
layouts, duplicate offsets, unresolved member sizes, conflicting indirect
offsets, and overlapping fields remain unavailable. The evaluator never
infers a fragment size from the register width or consumes the rest of the
parent as if it were a member.

The record layouts were cross-checked against Ghidra's Java PDB reader for
enregistered fields and LLVM's CodeView definition of the indirect recipe
([Ghidra `EnregisteredFieldOfSymbolDARMsSymbol`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PDB/src/main/java/ghidra/app/util/bin/format/pdb2/pdbreader/symbol/EnregisteredFieldOfSymbolDARMsSymbol.java),
[LLVM `SymbolRecord.h`](https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/DebugInfo/CodeView/SymbolRecord.h),
and [LLVM `CodeViewRegisters.def`](https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/DebugInfo/CodeView/CodeViewRegisters.def)).
HexLab performs the bounded type-layout proof and live memory read after
decoding those records.

Register or memory values remain unavailable when their required register or
type size is unknown, the register is absent, the type exceeds the 256-byte
preview bound, an address calculation overflows, or memory cannot be read in
full. Complete PE live-range extents are validated with the same section/image
mapping checks before they are translated. Rows without a live range are
omitted unless their lexical scope is unresolved;
unsupported CodeView register identifiers are not guessed. PDB rows duplicate
a DWARF row only when no same-name, same-kind DWARF row is already available.

Scalar previews are bounded to 256 bytes. Small values are displayed as
scalars and wider values as bytes. Register-backed wide values require enough
bytes from the debugger for the complete type.
