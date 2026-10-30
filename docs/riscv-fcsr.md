# RISC-V floating-point control and status state

`RiscvFcsrState` carries the low five accrued exception bits (`fflags`) and the
three-bit dynamic rounding mode (`frm`). The processor semantics API applies
decoded Zicsr operations to the standard `fflags` (0x001), `frm` (0x002), and
`fcsr` (0x003) views. Set and clear operations use the old value of the selected
view, writes through one alias preserve fields owned by the other alias, and
reserved high bits read as zero and are ignored when committing writes.

`accrue_riscv_fflags` merges flags with bitwise OR, preserving the sticky
architectural behavior across operations. It rejects flags outside NX, UF, OF,
DZ, and NV. The state helper does not decide when a floating-point operation
raises a flag; operation evaluators return those bits separately.

`resolve_riscv_rounding_mode` accepts static instruction modes 0 through 4.
Instruction mode 7 resolves through `frm`, which must then be 0 through 4.
Instruction encodings 5 and 6, and reserved dynamic `frm` values, return no
mode. The helper also checks the decoder's `reads_frm` fact against whether the
instruction requests dynamic rounding.

These functions model the register values and rounding-mode selection only.
They do not check privilege or extension enablement, deliver traps, or select a
platform reset state; callers supply the initial `RiscvFcsrState`.

`read_riscv_f32_register_value` and `write_riscv_f32_register_value` handle
binary32 values stored in an FPR. With FLEN=64, reads whose upper half is not
all ones produce canonical `0x7fc00000`; writes NaN-box the low word. With
FLEN=32, values are read and written without boxing. These helpers make the
register representation explicit for clients that feed raw FPR values into
the bit-pattern floating-point evaluators.
