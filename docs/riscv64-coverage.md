# RV32I and RV64I decoder coverage

HexLab now dispatches a fixed-width RV32I/M base-integer subset as well as the
existing RV64I/M and RV64IC paths. Select `Architecture::riscv32` with
`ExecutionMode::rv32` for RV32I; raw files accept `--arch rv32`, and little-
endian ELF32 images with `EM_RISCV` and no RVC flag select this mode. RV32
RV32M multiply/divide operations decode with typed source and destination
register effects. Their scalar semantics are exposed through
`evaluate_riscv_m_operation`: low and high multiply variants, signed and
unsigned division and remainder, divide-by-zero results, signed overflow, and
RV64 word-result sign extension follow M version 2.0. RV32 register facts and
memory address bases retain 32-bit width while using the
architectural `x0` through `x31` names. Direct branches and jumps participate
in the common reachable-analysis pipeline. RV32I/M rejects RV64-only LD/LWU/SD
and RV64 word operations. Compressed instructions are
explicitly unsupported in RV32 mode; an ELF32 image advertising RVC is left
without a decoder mode rather than decoded as fixed-width code.

HexLab includes a bounded, static decoder for RV64I base integer ISA (version
2.1), integer multiplication/division extension M (version 2.0), atomic
extension A (version 2.1), and the integer RV64C subset (version 2.0). The
Zifencei `FENCE.I` instruction is also decoded and formatted when its canonical
encoding is present; it has no explicit operands in the current instruction
model. The decoder accepts mixed 16-bit and
32-bit instruction encodings in RV64IC mode and models
register, immediate, base-plus-displacement memory, and PC-relative operands.
It records register reads and writes, memory direction, and control-flow class
for direct and indirect branches, calls, returns, and environment traps.

Supported base forms include U (LUI/AUIPC), J (JAL), I (JALR, loads,
OP-IMM, OP-IMM-32), B (conditional branches), S (stores), R (OP and OP-32),
FENCE, ECALL, and EBREAK. The M subset includes all RV64 register forms and
the RV64 word forms: MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU, MULW,
DIVW, DIVUW, REMW, and REMUW. RV64I shift-immediate encodings validate their
reserved upper bits and retain the architecturally sized shift amount.

The exact `FENCE.TSO` encoding (`fm=1000`, predecessor=`RW`,
successor=`RW`, and zero `rd`/`rs1`) is decoded and formatted as a distinct
opcode. Other nonzero FENCE modes remain unsupported. The accepted encoding
and ordering semantics follow the [RISC-V Unprivileged ISA manual](https://docs.riscv.org/reference/isa/v20240411/_attachments/riscv-unprivileged.pdf).

The A subset decodes LR.W/SC.W and all nine AMO arithmetic/logical operations
for RV32 and RV64, plus the corresponding doubleword forms for RV64. Typed
operand access and memory read/write direction are retained; LR.W and AMO.W
carry their 32-bit data width, and `aq`/`rl` ordering bits survive generic
dispatch and appear in assembly formatting. The current decompiler retains
these as explicit opaque atomic instructions rather than modeling reservation
sets, conditional success, or inter-hart memory ordering.

RV64I mode uses IALIGN=32; RV64IC mode uses IALIGN=16 and advances correctly
across mixed 16-bit and 32-bit instructions. The C subset covers integer
loads/stores, immediate and register arithmetic, shifts, conditional branches,
jumps, indirect jumps, and EBREAK. Floating-point compressed encodings remain
unsupported. It reads the RISC-V length prefix before decoding: 48-bit,
64-bit, and longer encodings are never mistaken for ordinary 32-bit
instructions. They are reported as unsupported (or truncated when a detected
variable-length instruction is incomplete).

The decoder includes the six unprivileged Zicsr forms: CSRRW, CSRRS, CSRRC,
CSRRWI, CSRRSI, and CSRRCI. It retains the 12-bit CSR number as an unsigned
operand, the zimm field as an unsigned five-bit operand, and separate CSR
read/write effects. CSRRW/CSRRWI suppress the CSR read when `rd=x0`; CSRRS,
CSRRC, CSRRSI, and CSRRCI suppress the CSR write when their register or
immediate source is zero. CSR address bits 11:10 are checked for the
architecture-defined read-only encoding: a CSR operation that requests a
write to an address with bits `11` is rejected, while zero-source CSRRS/CSRRC
forms remain reads and are accepted. This check is based only on the encoded
access class. The decoder does not check current privilege, CSR existence,
implementation-specific access rules, or whether a CSR is implemented by a
particular hart. The rules follow the [Zicsr instruction semantics](https://docs.riscv.org/reference/isa/unpriv/zicsr.html)
and the [CSR address mapping conventions](https://docs.riscv.org/reference/isa/priv/priv-csrs.html).
Generic formatting uses standard names for the common supervisor and machine
status/trap setup and handling CSRs (`sstatus`, `sie`, `stvec`, `scounteren`,
`sscratch`, `sepc`, `scause`, `stval`, `sip`, `satp`, and the corresponding
`mstatus`/machine trap CSRs). Other CSR numbers retain their numeric spelling.
The decompiler models only the floating status aliases `fflags`, `frm`, and
`fcsr` as separate status-register SSA fields; other CSR contents remain
opaque. Naming does not imply that a CSR exists on a particular hart or is
accessible at the current privilege level.

The bounded scalar F/D slice accepts FLW/FSW and FLD/FSD, S/D arithmetic,
square root, sign injection, min/max, the four fused multiply-add forms,
FEQ/FLT/FLE/FCLASS, integer and S/D conversions, and raw integer/FP moves.
`evaluate_riscv_fmv_instruction` evaluates the raw-bit `FMV.X.W`/`FMV.W.X`
transfers in RV32/RV64 and `FMV.X.D`/`FMV.D.X` in RV64. W-to-X sign-extends
the low word; X-to-FPR W writes return a NaN-boxed 64-bit value. The adapter
validates decoded GPR/FPR operands and read/write facts, with x0 treated as
zero and its writes suppressed. Callers still sample nonzero registers and
commit the result.
It validates static rounding modes and retains the selected mode, including
dynamic `dyn`. FPR operands use a distinct physical 64-bit bank; S operations
carry 32-bit values. Rounding-sensitive dynamic conversions read the three-bit
`frm` alias; exact FCVT.D.W/WU and non-rounding FCVT.D.S do not. Possible
`fflags` writes read the accrued prior flags and remain a separate five-bit
status register effect. FCVT.D.W/WU are exact and leave flags untouched.
`evaluate_riscv_fsgnj_operation` implements the S/D FSGNJ, FSGNJN, and FSGNJX
sign-bit operations on raw encodings; its instruction adapter checks the
decoded three-FPR access pattern. They preserve magnitude bits without NaN
processing or FFLAGS updates, and callers supply the register values.
FCVT and FCLASS lifting preserves integer signedness, low-word truncation,
RV64 W/WU result sign extension, rounding inputs only where the ISA uses them, and separate
conservative exception formulas; see `riscv-decompiler.md` for encodings.
`evaluate_riscv_fclass` and its decoded-instruction adapter classify raw
binary32/binary64 encodings into the ten architectural FCLASS one-hot bits,
including signed zeros, subnormals, infinities, and signaling versus quiet
NaNs. This bit-level operation does not use host floating-point or update
`fflags`; the caller supplies a raw binary32 value with no upper bits set or a
raw binary64 value. NaN-box validation for scalar S operands remains outside
this evaluator.
The Zfa FROUND.S/D and FROUNDNX.S/D round-to-integral forms are decoded with
their selected rounding mode and lifted as typed floating-point intrinsics.
The processor semantics API also evaluates their raw binary32/binary64 bit
patterns for a caller-resolved rounding mode, preserving signed zero and NaN
payloads while quieting signaling NaNs. FROUND reports NV for signaling NaNs;
FROUNDNX additionally reports NX when a non-NaN finite input changes. Dynamic
`frm` selection is represented in SSA, and known effective modes allow the
optimizer to fold non-NaN value and exception formulas while preserving the
sticky flag update; see [Zfa round-to-integral evaluation](riscv-zfa-rounding.md).
RV64F NaN-boxing is not modeled. The decoder does not evaluate IEEE-754 results
or compute precise exception flags for general floating arithmetic. Q-format
operations, compressed floating forms, and RV32-only absent forms remain
unsupported or invalid according to their encoding.

RVV 1.0 configuration forms VSETVLI/VSETIVLI/VSETVL and an integer elementwise subset are enabled. The data subset includes VADD.VV/VX/VI, VSUB.VV/VX, VRSUB.VX/VI, and VAND/VOR/VXOR in VV/VX/VI forms. Integer mask comparisons now include VMSEQ/VMSNE in VV/VX/VI, VMSLTU/VMSLT in VV/VX, VMSLEU/VMSLE in VV/VX/VI, and VMSGTU/VMSGT in VX/VI. These forms follow the base V extension's non-orthogonal operand availability: reserved immediate less-than and vector greater-than encodings remain invalid. The decoder retains vector-register operands without assuming fixed VLEN, distinguishes scalar GPR and sign-extended five-bit immediate forms, and records whether masked operations implicitly read v0. The decompiler emits named vector intrinsics with explicit source, mask, and destination effects; it does not invent lane width, active length, mask-result shape, tail/mask policy, or vtype state semantics. Segmented, whole-register, fault-only-first, floating-point, and other vector memory forms, narrowing and other elementwise operations remain outside this subset. Unit-stride integer VLE/VSE and strided integer VLSE/VSSE forms are decoded with explicit width, scalar base and stride operands, memory effects, and masked-v0 reads. A bounded helper plans active unit/strided element addresses from caller-supplied VLEN, vtype, vl, vstart, base/stride, and predicate bytes; it rejects invalid EMUL/address wrap and does not perform memory accesses or model faults. The added shifts are VSLL/VSRL/VSRA in VV/VX/VI forms (the shift immediate is an unsigned five-bit amount); VMINU/VMIN/VMAXU/VMAX are accepted in VV/VX forms only. Masked encodings record the implicit v0 read, and unmasked encodings do not. Reserved VI min/max forms and other reserved encodings in recognized integer operation classes are invalid; operand classes and RVV operations outside this selected subset remain unsupported.

The single-width integer multiply family now includes VMUL, VMULH, VMULHU, and
VMULHSU in VV/VX forms. The decoder records both vector source reads, or the
scalar GPR read for VX, the vector destination write, and an implicit v0 read
when masked. Generic formatting and decompilation preserve the mnemonic, input
registers, mask, and destination effects. Analysis consumes the ordinary
register-effect records; it does not infer lane values or fixed vector width.
VI multiply forms remain unsupported. Non-accumulating widening multiply is
supported for VWMULU, VWMULSU, and VWMUL in VV/VX forms. The decoder and
decompiler retain the widening result and destination, source, mask, and
configuration effects. The bounded evaluator computes full 2*SEW products for
SEW 8/16/32 and destination EMUL at most 8, preserving masked, prestart, and
tail lanes; SEW 64 remains symbolic because it requires 128-bit result lanes.
Vector divide and remainder VV/VX forms are decoded, formatted, lifted, and
available in the bounded integer lane evaluator.

The non-widening integer multiply-accumulate family now includes VMACC, VNMSAC,
VMADD, and VNMSUB in VV/VX forms. Their destructive destination is recorded as
an input dependency alongside both multiplicands, and masked forms retain the
implicit v0 read. The lane evaluator computes the low SEW bits of each product
and accumulation, preserves inactive and tail destination lanes, and uses the
distinct accumulator-versus-multiplicand equations for the two instruction
pairs. Decode forms and operand ordering follow the official RVV 1.0
[multiply-add specification](https://docs.riscv.org/reference/isa/v20240411/unpriv/v-st-ext.html#vector-single-width-integer-multiply-add-instructions).
Seven widening integer multiply-accumulate forms are decoded, formatted, and
lifted as named opaque vector operations: `VWMACCU.VV/VX`, `VWMACC.VV/VX`,
`VWMACCSU.VV/VX`, and the VX-only `VWMACCUS.VX`. The bounded lane evaluator
computes exact signed/unsigned products plus the old 2*SEW accumulator for
SEW 8/16/32 when destination EMUL is at most 8. It retains masked and
prestart lanes and reports the 16/32/64-bit result element width. SEW 64 and
physical register-group legality remain outside that evaluator.

Decompiler typing for the 84 decoded integer elementwise forms is shared across
arithmetic, bitwise, shift, min/max, multiply/divide/remainder, and comparison
families. Data outputs are opaque width-independent vectors; comparison outputs
identify predicate mask bits without assuming VLEN or a lane count. The lifter
preserves masked-v0, scalar vector-configuration and old-destination dependencies,
including when v0 aliases a source or destination. Configuration writes such as
vstart remain scalar in type recovery. This is separate from the optional bounded
lane evaluator: decompilation does not evaluate vector lanes or introduce
previously unsupported decoder forms. See [RISC-V decompiler lifting](riscv-decompiler.md).

The RVV mask-register logical group now decodes the eight unmasked `.mm`
operations `vmand`, `vmnand`, `vmandn`, `vmxor`, `vmor`, `vmnor`, `vmorn`,
and `vmxnor`. They require OPMVV and `vm=1`; the reserved masked forms are
invalid. Destination and sources are vector-register operands with mask-value
typing in the decompiler, and `vl`, `vtype`, and `vstart` effects are retained.
The old destination dependency preserves elements before `vstart`; lane
execution and concrete mask bitstrings are not evaluated.

The RVV gather/slide group now decodes `vrgather.vv/vx/vi`, `vslideup.vx/vi`,
and `vslidedown.vx/vi`, including unsigned zero-extended immediate offsets,
masked-v0 reads, and vector-configuration dependencies. Generic disassembly
prints the exact form and the decompiler retains each operation as a named
intrinsic. Runtime lane movement, register-group overlap validation, and
slide1 forms remain unsupported.

Single-field indexed integer `vluxei*.v`, `vloxei*.v`, `vsuxei*.v`, and
`vsoxei*.v` decode for 8/16/32/64-bit index EEW. Operand typing preserves the
vector index register, scalar base, index width, mask and vector-configuration
dependencies. Generic formatting retains the ordered/unordered mnemonic and
width; decompilation emits named indexed-memory intrinsics with the correct
read/write effect. A bounded address planner checks index EMUL, lane/mask
shapes, and XLEN address addition. It returns addresses only and does not
perform memory access or model ordering, aliasing, faults, or partial updates.
Segmented, whole-register and fault-only-first vector memory remain unsupported.

Privileged and custom extensions remain disabled. Known unsupported encodings return unsupported with an
explanatory reason; reserved encodings in implemented base formats return
invalid. This is a decoder milestone, not a full RISC-V backend, assembler,
emulator, ABI analyzer, or decompiler.

Literal encoding tests are in `tests/riscv64_decoder_tests.cpp` and
`tests/processor_modes_tests.cpp`; they cover
every implemented instruction format, selected register and memory effects,
branch target reconstruction, integer M/A/C forms, partial instructions, invalid
encodings, alignment, explicit unsupported extension cases, all six Zicsr
opcodes, CSR read/write suppression, unsigned CSR/zimm operands, RV32/RV64/RV64C
dispatch, and assembly formatting. Existing RVV fixtures cover the earlier add/logical/configuration/unit-stride subset, including VV/VX/VI typing, immediate sign extension, masked v0 reads, reserved forms, generic dispatch, and assembly spelling. The integer comparison and single-width multiply additions have compile-only evidence and remain unverified by fixtures.

For ELF64 little-endian images with `e_machine=EM_RISCV`, the generic
processor dispatcher selects RV64IC mode when EF_RISCV_RVC is set, otherwise
RV64I mode. Decoded instructions feed the common listing and reachable-control-
flow pipeline, including direct branch and call targets. For fixed-width
RV32I/RV64I code, reachable analysis also resolves unrelocated `AUIPC`/`JALR`
and `AUIPC`/`ADDI`/`JALR` call or jump sequences when the destination register
chain is explicit and contiguous. Resolution uses XLEN-width arithmetic and
JALR's low-bit clearing; recovered call targets feed function discovery. The
bounded lookback declines inference if any instruction in the sequence
overlaps an ELF/Mach-O relocation or dyld fixup. RV64IC compressed-code
lookback is not supported. This does not resolve general relocation pairs,
arbitrary register dataflow, or indirect targets built by other instruction
sequences. Project references and derived analysis facts validate and
round-trip the RV64 register bank. The ELF flag-derived mode survives project
analysis context construction. Other ELF classes and byte orders remain
inspectable as metadata but do not select this decoder. ABI register aliases
and the disabled ISA extensions listed above remain outside this integration.

RV32/RV64 decode the XLEN-width `sh1add`, `sh2add`, and `sh3add` Zba address
generators. RV64 additionally decodes `add.uw`, `sh1add.uw`, `sh2add.uw`,
`sh3add.uw`, and `slli.uw`. The semantic evaluator performs XLEN-width modular
arithmetic and zero-extends the low 32-bit source for `.uw` forms. The typed
lifter keeps shifts and additions explicit, and reference propagation carries
known mapped addresses through these operations only when all required source
values are known. This does not infer an unknown runtime index. Encodings and
operations follow the frozen [Zba extension specification](https://github.com/riscv/riscv-bitmanip/blob/main/bitmanip/zba.adoc).

The scalar Zbb 1.0 integer subset is now covered across RV32 and RV64. Along
with the existing CLZ/CTZ/CPOP operations, decode and generic formatting cover
ANDN/ORN/XNOR, signed and unsigned MIN/MAX, SEXT.B/SEXT.H/ZEXT.H, ROL/ROR/RORI,
ORC.B, and XLEN-specific REV8. RV64 additionally includes ROLW/RORW/RORIW;
their evaluator returns the ISA-required sign-extended 32-bit result. The
portable semantic helpers evaluate these operations on raw XLEN-bit values,
including modulo-width rotates and byte-wise OR-combine. The decoder retains
register/immediate access facts and rejects reserved shift and unary encodings.
These scalar results are available to callers of the semantics API; general
decompiler lifting of the newly added operations, Zbs single-bit instructions,
Zbc carry-less multiply, Zbf funnel shifts, cryptographic extensions, and
privileged instructions remain unsupported.

## Reference

The opcode and encoding scope follows the versioned [RISC-V Unprivileged ISA
Manual, Version 20240411](https://docs.riscv.org/reference/isa/v20240411/unpriv/unpriv-index.html),
especially the RV64I and M chapters and the [V Standard Extension, Version 1.0](https://docs.riscv.org/reference/isa/v20240411/unpriv/v-st-ext.html). The vector comparison subset retains the operand availability listed by that specification. The manual identifies RV64I base integer
ISA version 2.1 and M version 2.0. RISC-V ISA modules are versioned separately;
this implementation intentionally does not claim compatibility with every
extension or privileged specification revision.

Atomic encodings and ordering behavior follow the ratified [A extension
specification, version 2.1](https://docs.riscv.org/reference/isa/unpriv/a-st-ext.html).



The integer reduction subset includes `vredsum.vs`, `vredand.vs`, `vredor.vs`, `vredxor.vs`, `vredminu.vs`, `vredmin.vs`, `vredmaxu.vs`, and `vredmax.vs` OPMVV forms in both masked and unmasked encodings. Masked forms read `v0`; the generic decompiler retains that predicate and emits named reduction intrinsics. The bounded lane evaluator seeds from `vs1[0]`, skips inactive `vs2` lanes, wraps sums to SEW, preserves the old destination outside element zero, and rejects nonzero `vstart`. Dynamic vtype shape and register-group alignment are not checked at decode time. Encoding/effect behavior follows the [RISC-V V extension specification](https://docs.riscv.org/reference/isa/unpriv/v-st-ext.html).

The RVV mask unary/count subset now decodes `vcpop.m`, `vfirst.m`,
`vmsbf.m`, `vmsof.m`, `vmsif.m`, `viota.m`, and `vid.v` for RV32 and RV64.
`vcpop.m`/`vfirst.m` expose their GPR destination, mask source, and optional
`v0` predicate; the prefix/index operations expose vector destination/source
facts and preserve masked `v0` reads. `vid.v` validates its reserved `vs2`
field and has no source-vector operand. These forms retain their vector
configuration reads and flow through generic opcode dispatch and assembly
formatting. The decoder does not evaluate lane values, enforce `vstart` rules,
check mask/vector register overlap, or infer extension availability from ELF
flags. Encodings follow the ratified [RVV 1.0 specification](https://docs.riscv.org/reference/isa/unpriv/v-st-ext.html#vector-mask-instructions).

The scalar Zfa `fminm.s/d` and `fmaxm.s/d` forms are also decoded, retaining FPR
inputs and accrued floating status effects. Their canonical-NaN behavior for
NaN inputs is represented by typed decompiler intrinsics rather than evaluated.
The quiet comparison forms `fleq.s/d` and `fltq.s/d` are decoded and lifted
with GPR results and accrued `fflags` dependencies. Their intrinsic semantics
distinguish quiet from signaling NaNs: quiet NaNs do not raise NV, while
signaling NaNs may. The other Zfa scalar format families (H and Q) remain
outside this F/D decoder.

The scalar Zbs single-bit subset decodes `bclr`, `bext`, `binv`, and `bset` in
register-index forms and `bclri`, `bexti`, `binvi`, and `bseti` in immediate
forms for RV32 and RV64. Encodings validate each operation's distinct funct
fields, and immediate indexes retain unsigned five-bit RV32 or six-bit RV64
width. Register effects are ordinary XLEN GPR reads and writes, including
`bext`'s zero-or-one result. `evaluate_riscv_zbs_operation` computes the
XLEN-masked bit operation and masks register indexes by XLEN as required by
the ISA. Typed decompiler lifting now lowers all eight forms to width-aware
bit expressions, explicitly masking register and immediate indexes to XLEN
before selecting the bit. RV64 word forms are not implemented.

The scalar Zbkb packing slice decodes `pack` and `packh` for RV32/RV64, plus
RV64-only `packw`. The decoder records both source GPR reads and the destination
write, and generic formatting uses the canonical mnemonic. The semantic helper
packs the low XLEN/2 bits from each source for `pack`, the low bytes for
`packh` (zero-extending the 16-bit result), and the low 16-bit halves for
`packw` (sign-extending the resulting 32-bit value). Decompiler lifting remains
unsupported. Encodings and behavior follow the ratified [Scalar Cryptography
specification, version 1.0.1](https://docs.riscv.org/reference/isa/unpriv/scalar-crypto.html).

The scalar Zbc subset decodes `clmul`, `clmulh`, and `clmulr` for RV32 and RV64, retains both source reads and the destination write, and formats the canonical mnemonics. A raw-bit semantic helper evaluates the low, high, and reversed carry-less product windows without relying on a compiler-specific double-width integer; typed decompilation now emits width-correct `clmul`, `clmulh`, or `clmulr` operations over both source values. The decoder does not infer extension availability from an ELF `e_flags` value. Encodings and result windows follow the frozen [RISC-V Zbc specification](https://github.com/riscv/riscv-bitmanip/blob/main/bitmanip/zbc.adoc).

The Zicond `czero.eqz` and `czero.nez` R-type forms decode for RV32 and RV64 with both GPR inputs and the destination write recorded, and format with their canonical dotted mnemonics. `evaluate_riscv_zicond_operation` evaluates their XLEN-masked raw-bit result. Decompiler lifting emits typed conditional selects that choose the value source or XLEN-wide zero according to the second source's zero/nonzero state. The decoder accepts only funct7 `0000111` with funct3 `101` or `111`; reserved funct3 values and RV64 word encodings remain unsupported. The operation semantics follow the ratified [Zicond specification, version 1.0](https://docs.riscv.org/reference/isa/unpriv/zicond.html).
