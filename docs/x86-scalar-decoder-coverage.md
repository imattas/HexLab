# x86 scalar decoder coverage

The native VEX integer subset includes the BMI1 `ANDN`, `BEXTR`, `BLSI`,
`BLSMSK`, and `BLSR` families with register/memory source effects, canonical
formatting, typed decompiler intrinsics, and caller-driven result/flag
evaluation. See [BMI1 coverage and boundaries](x86-bmi1.md).

## String port I/O

INS/INSB/INSW/INSD (`6C/6D`) and OUTS/OUTSB/OUTSW/OUTSD (`6E/6F`) decode
across the shared 16-, 32-, and 64-bit contexts. Operand width selects byte
or mode-sized transfers, while address-size override selects DI/SI and the
repeat count register width. INS writes through ES:DI; OUTS reads from the
overridden or default data segment at SI. Both retain DX as the port input,
index updates, and REP/REPE/REPNE count effects. Typed lifting retains these
as `x86_string_ins_*` / `x86_string_outs_*` intrinsics with memory direction
and dynamic inputs explicit. Port access, I/O privilege checks, and repeated
iteration execution are not evaluated by the lifter.

The original x86 scalar decoder is shared by 16-bit, 32-bit, and 64-bit execution contexts. Operand size, address size, stack size, legacy prefixes, REX, and ModRM/SIB decoding remain mode-specific. Instructions that are not covered by the typed decoder may be retained by the separately marked display-only fallback; fallback results do not claim typed operand or register effects.

`CPUID` (`0F A2`) decodes in the 16-, 32-, and 64-bit contexts with implicit
EAX/ECX selector reads and EAX/EBX/ECX/EDX result writes. In long mode, each
32-bit result also records the architectural zero-extension into its 64-bit
GPR. Typed lifting emits an `x86_cpuid` intrinsic with symbolic outputs; it
does not query the analysis host or claim a particular processor's feature
enumeration. CPU-generation and CPUID-feature gating remain outside the
decoder.

The typed decoder covers register, memory, and accumulator `XCHG` forms (`86`, `87`, and `90`–`97`) in all three modes. The 16- and 32-bit contexts use their default operand width with `66` selecting the other legacy width. In long mode, `REX.W` selects 64-bit operands and `REX.B` extends the accumulator-form register. Byte forms preserve AH/CH/DH/BH without REX and select SPL/BPL/SIL/DIL with REX. A bare `90` remains the canonical NOP, `F3 90` remains PAUSE, and `REX.B 90` is the accumulator exchange encoding. Memory forms retain the current mode's effective address, segment, and read/write effects. `LOCK` is accepted for memory forms and rejected for register-only forms; the XCHG opcode plus a memory operand identifies its architectural implicit atomicity.

The accumulator sign-extension encodings `98` and `99` now expose their implicit register effects. Their operand-size-selected forms are:

| Operand width | `98` | `99` |
| --- | --- | --- |
| 16 | CBW: AL → AX | CWD: AX → DX:AX (DX is written) |
| 32 | CWDE: AX → EAX | CDQ: EAX → EDX:EAX (EDX is written) |
| 64 | CDQE: EAX → RAX | CQO: RAX → RDX:RAX (RDX is written) |

`66` selects the legacy alternate width; in long mode the default is 32 bits, `66` selects 16 bits, and `REX.W` selects 64 bits. These instructions do not write flags.

`LAHF` (`9F`) is decoded as a typed status transfer in 16-, 32-, and 64-bit
contexts. It reads the mode-width FLAGS value and writes only AH. The decoded
instruction evaluator returns SF/ZF/AF/PF/CF in their matching AH bit positions,
forces bit 1, and clears bits 3 and 5; all other FLAGS bits are ignored. The
decompiler retains the transfer as an `lahf` intrinsic with an explicit AH
output value. `SAHF` (`9E`) is also decoded with an AH input and FLAGS output;
the incoming FLAGS value is an explicit read because all bits outside
CF/PF/AF/ZF/SF are preserved. Its decoded evaluator replaces only those five
bits from AH. The decompiler represents it as a `sahf` intrinsic whose output
expression retains both the incoming FLAGS and AH values, and retains the
existing FNSTSW/SAHF comparison-chain recognition. Runtime CPU-feature
availability for LAHF/SAHF is not checked.

`CLC`, `STC`, and `CMC` update CF, while `CLD` and `STD` update DF. The typed
decoder records the prior whole FLAGS value as an input so unaffected bits are
preserved, and the decoded evaluator applies the single-bit update with the
mode's FLAGS width. The decompiler emits an explicit flags-control intrinsic
and output value. Feature availability and full machine-state execution remain
outside this scalar evaluator.

`CLC`, `STC`, and `CMC` update CF, while `CLD` and `STD` update DF. The typed
decoder records the prior whole FLAGS value as an input so unaffected bits are
preserved, and the decoded evaluator applies the single-bit update with the
mode's FLAGS width. The decompiler emits an explicit flags-control intrinsic
and output value. Feature availability and full machine-state execution remain
outside this scalar evaluator.

The regression suites check rendered operands, mode-dependent widths and addresses, typed register and memory effects, REX/high-byte interactions, LOCK validity, and every truncation of each fixture. Invalid, truncated, unsupported, and display-only results remain distinct. This coverage addition does not imply complete x86 ISA coverage; vector, system, privileged, and other unimplemented forms still require separate decoder work.

The typed stack-frame family now includes `PUSHF`/`POPF`, `PUSHA`/`POPA` (and 32-bit `PUSHAD`/`POPAD`), and `ENTER`. Stack value width follows each execution mode's operand-size rules independently of stack-address width. PUSHA/POPA retain their eight-slot effects and the architecturally discarded saved-SP slot; ENTER retains both encoded immediates and records nested frame-chain reads while masking the nesting level to five bits. PUSHA/POPA are rejected in long mode. These are decoded facts; privileged flag filtering and full runtime stack/memory execution remain outside this decoder slice.

The decompiler lifts x86 `PUSH`/`POP`, `PUSHF`/`POPF`, `PUSHA`/`POPA`, `ENTER`, and `LEAVE` as mode-neutral stack intrinsics. Each intrinsic carries the decoded stack value width, stack pointer input/output, a stack-slot memory expression where the decoder supplies enough metadata, and the decoded memory read/write effect. `PUSH`/`PUSHF` address the slot below the incoming stack pointer; `POP`/`POPF` address the incoming top slot; `LEAVE` uses BP as the load base. The grouped operations and `ENTER` remain explicit intrinsics so their multi-slot/frame-chain behavior is not misrepresented as one ordinary load or store. Near `CALL` and `RET` remain control-flow statements while their implicit return-address push/read is now retained in typed stack-effect metadata and tied to the whole-memory SSA input. Pseudocode reports the stack slot and transfer-time SP delta; `RET imm16` also reports callee cleanup bytes. Calls still invalidate memory for possible callee writes, and far calls/returns or unavailable stack widths retain no near-transfer stack effect. Stack values are not simulated and the caller's post-return SP remains unchanged in the atomic call model.

The custom decoder now also recognizes common x87 instruction forms in the D8–DF escape families. It keeps ST(0)–ST(7) in a dedicated typed register bank, reports regular x87 stack pushes/pops, and retains exact memory operand widths and mode-specific addressing. See [x87 decoder coverage](x87-decoder-coverage.md) for supported groups and boundaries.

The decoder supports double-precision scalar shifts `SHLD` and `SHRD` in all three x86 modes: `0F A4/A5` and `0F AC/AD`, with matching-width register or memory destinations, a same-width ModRM register source, and either `imm8` or `CL` counts. The decoder records an incoming FLAGS dependency for a zero effective immediate count and for every CL form, since those counts can preserve FLAGS. The pure evaluator masks counts to five bits except for 64-bit operations (six bits), preserves flags for a masked zero count, returns undefined result/flag state for counts above operand width, and reports the defined CF/SF/ZF/PF plus count-one OF values independently. `evaluate_x86_double_shift_instruction` connects decoded SHLD/SHRD operands to that evaluator: callers provide the destination and source values, and provide the runtime count only for CL forms. It does not read memory or mutate machine state. For register destinations with immediate counts, the decompiler now exposes the exact fixed-width result formula, including the zero-count destination preservation and count-equals-width source result. Flags remain explicit outputs: zero count reuses the incoming FLAGS value, while nonzero count flag bits remain unknown. CL-count and memory-destination forms remain named intrinsics because runtime count constraints and memory/atomic effects are not represented as ordinary expressions.


## MOVBE scalar memory moves

The original scalar decoder supports `MOVBE r16/32/64,m16/32/64`
(`0F 38 F0 /r`) and the reversed-direction store (`0F 38 F1 /r`). The
ModRM r/m operand must be memory; register-only and memory-to-memory forms
are not accepted. Widths follow the execution mode's ordinary operand-size
rules: legacy16 defaults to 16, legacy32 and long mode default to 32, `66`
selects the alternate 16/32 width, and REX.W selects 64 in long mode. There
is no byte form. Address-size overrides, segment selection, SIB, displacement,
REX register extension and instruction-length/truncation rules use the
existing scalar address parser.

F2 with these map/opcode bytes selects the separate CRC32 scalar operation;
it cannot silently become MOVBE. F3 and LOCK are invalid for MOVBE. MOVBE does not read
or write FLAGS. The decode retains one memory read or write and the matching
register/address dependencies. CPU-feature availability is not checked.

The decompiler lowers the load/store using typed `bswap16`, `bswap32`, or
`bswap64` on the source value, followed by an assignment or memory store.
A load narrower than the mode's full GPR view also defines that view in
parallel: long-mode 32-bit loads zero the upper 32 bits, while 16-bit loads
preserve the incoming upper bits in legacy32 and long mode. These formulas
read the pre-instruction state even when the address uses the destination
register. Other cross-width GPR alias relationships retain the shared IR's
existing limits. Malformed mode/width/access/output shapes remain opaque.
The existing typed memory IR retains access and SSA effects; this does not
execute memory faults, segment checks or CPU feature exceptions.

Opcode, operand, flag and prefix behavior follows Intel's primary
[MOVBE reference in SDM Volume 2B](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).
Broader scalar extensions, APX variants and independent encoding-oracle
validation remain outside this slice. The SSE4.2 scalar CRC32 addition is
covered in [SIMD-extension coverage](x64-simd-coverage.md#sse42-scalar-crc32c).

## MOVSXD in long mode

Long mode opcode 63 /r decodes both MOVSXD widths. Without REX.W, the ModRM destination and source are 32-bit; with REX.W, a 32-bit source is sign-extended into the 64-bit destination. REX.R/B extensions and ordinary register-or-memory source addressing remain available. CPU-feature availability is not checked.

In 16-bit and 32-bit execution modes, opcode 63 decodes ARPL with its architecturally fixed 16-bit operands: ModRM r/m16 is read and written, while the ModRM reg16 source is read. The 66 operand-size override does not change ARPL's operand width. It writes the ZF fact; arithmetic flag bits are not claimed. LOCK is rejected. Long mode interprets the opcode as MOVSXD instead. The lifter retains ARPL as `x86_arpl` with its destination/source and implicit writes explicit; its conditional low-two-bit update is not expanded into ordinary expressions.

The legacy-only AAM (`D4 ib`) and AAD (`D5 ib`) encodings now decode their explicit radix byte and implicit AL/AH effects. AAM reads AL and writes quotient to AH and remainder to AL; AAD reads both bytes and writes the adjusted result to AL while clearing AH. Both retain a flags-write effect and are lifted as `x86_aam`/`x86_aad` intrinsics because radix-zero exceptions and exact per-flag definedness are not represented by the scalar expression model. The radix byte is preserved as encoded, including zero. These encodings are rejected in long mode; LOCK and repeat prefixes remain invalid.

BOUND (`62 /r`) decodes in legacy 16/32-bit modes with a GPR index operand and a memory-only bounds pair. Operand size selects the index width and each bound width; the single typed memory operand spans both values (32 bits for a 16-bit index, 64 bits for a 32-bit index). Register ModRM forms are invalid. The instruction is classified as trap flow for its bounds exception, retains a memory read, and leaves flags unchanged. Its lifter intrinsic is `x86_bound`. Opcode 62 is the EVEX prefix in long mode, so BOUND is invalid there.

`evaluate_x86_aam_aad_instruction` evaluates the decoded AL/AH results and
returns the defined PF/ZF/SF output bits with their mask. AAM with radix zero
reports a divide error and no committed outputs. AF/CF/OF remain explicitly
undefined; the helper does not perform fault delivery or update machine state.

Legacy LES (`C4 /r`) and LDS (`C5 /r`) now decode only memory far pointers in 16/32-bit modes. Operand size selects the GPR offset width; the memory operand spans that offset plus a 16-bit selector. The GPR destination and ES (LES) or DS (LDS) are both recorded as writes, and the pointer is a memory read. Register ModRM forms are rejected. The lifter retains the far transfer as `x86_les`/`x86_lds` intrinsics with explicit output-register effects; selector loading and its descriptor checks remain opaque. In long mode C4/C5 are parsed as VEX prefixes, never as LES/LDS; only the existing VEX whitelist is accepted.

## POPCNT decoded evaluation

## Conditional data moves

The scalar decoder recognizes all `CMOVcc` forms (`0F 40`–`0F 4F`) and
`SETcc` forms (`0F 90`–`0F 9F`) in 16-, 32-, and 64-bit modes. Both retain
the exact four-bit x86 condition code and a FLAGS read dependency. CMOVcc
uses the mode-selected operand width, a read/write destination register (it
is preserved when the condition is false), and a register or memory source.
SETcc writes an 8-bit register or memory destination. This change records
decoder semantics only; conditional value selection remains unsupported by
the scalar lifter. Prefix validation continues to reject repeat prefixes
outside explicitly supported opcode forms.

The decoded POPCNT evaluator accepts 16-, 32-, or 64-bit register/memory source widths and a caller-supplied source value after any memory read. It returns the count in the destination width and updates CF, PF, AF, ZF, SF, and OF: the five non-ZF bits are cleared and ZF is set exactly when the masked source is zero. Other FLAGS bits are preserved from the caller's incoming value. Decoder effects now mark FLAGS as both read and written to represent that preservation. The helper does not perform memory access, apply the destination/FLAGS outputs to runtime state, or gate on CPUID feature bits.
BSF/BSR and F3 TZCNT/LZCNT scans now have width-specific typed result
intrinsics for 16-, 32-, and 64-bit forms. Their FLAGS outputs explicitly
preserve unaffected bits, define ZF (and CF for TZCNT/LZCNT), and retain
architecturally undefined bits as unknown values. See [bit-scan lifting](x86-bit-scan-lifting.md).

Register-form `BT`, `BTS`, `BTR`, and `BTC` now lift exact selected-bit and
destination formulas at 16/32/64-bit widths. Their output keeps CF exact,
preserves non-arithmetic FLAGS bits, and represents the other arithmetic flags
as undefined. See [register bit-test lifting](x86-bit-test-lifting.md).
