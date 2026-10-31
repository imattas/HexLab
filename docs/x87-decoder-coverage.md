# x87 Decoder Coverage

HexLab's original x86 decoder recognizes the D8–DF x87 escape families in 16-bit, 32-bit, and 64-bit execution contexts. It reuses the custom ModRM/SIB decoder, so effective address size, base/index, displacement, and segment overrides are retained as typed memory operands. The decoder does not delegate x87 decoding to Capstone.

Supported forms include the memory arithmetic and compare groups; integer and real loads/stores; 80-bit extended loads/stores and packed BCD forms; environment/control-word and saved-state forms; register-stack arithmetic, comparisons, loads, exchanges, stores, conditional moves, and common constants/transcendentals; plus FCOMI/FUCOMI and their popping variants. Memory operands carry exact bit widths, including 16/32/64/80-bit data and the 14/28-byte environment or 94/108-byte save areas.

Standalone `FWAIT` (`9B`) is decoded as a waiting x87 operation and reads the status and control words. Waiting versus FN-prefixed non-waiting forms is explicit in instruction metadata. Caller-owned helpers resolve pending unmasked exceptions, select native `#MF` or legacy IRQ13 mode, preserve status, and gate TOP/tag retirement; the decompiler exposes a symbolic pending-exception trap edge. Processor/task-switch delivery and exception state are not automatically executed. See [caller-owned pending exception semantics](x87-pending-exceptions.md).

The register model adds typed `x87` (`st` through `st(7)`), `x87_status` (`fsw`), `x87_control` (`fcw`), and `x87_tag` (`ftw`) banks. Instructions expose explicit operand access, implicit ST(0) reads/writes, EFLAGS effects for compare/move forms, and `x87_stack_delta` for pushes and pops. Push/pop effects also read and write the status and tag banks to represent TOP/tag changes; FDECSTP/FINCSTP report status effects without changing data registers or stack depth. D9 transcendental, remainder, scaling, and rounding operations report FCW reads and FSW read/writes for control-dependent results and sticky exception/status updates; their explicit push/pop effects remain separately represented by `x87_stack_delta`. FCOM/FCOMP/FUCOM-family comparisons report status effects, while FCOMI/FUCOMI variants additionally report EFLAGS writes. FLDENV/FRSTOR restore the relevant environment banks; FNSTENV/FNSAVE report environment reads and their post-save state changes; control/status-word load/store instructions report their bank effects. Formatting uses the decoded mnemonic and explicit memory-size qualifiers.

The shared decompiler lifts non-popping real `FADD`, `FMUL`, `FSUB`, `FSUBR`, `FDIV`, and `FDIVR` to typed 80-bit SSA assignments. Register and memory forms preserve destination and operand direction, including reversed subtraction/division and implicit ST(0) for memory forms. `FSQRT` retains a typed 80-bit unary result together with FCW input and FSW output effects. Other decoded x87 operations remain named `x87_<mnemonic>` intrinsics. Stack-register operands use an 80-bit floating type; real memory accesses retain their encoded 32/64/80-bit widths, while integer forms such as FILD/FIADD/FISTP retain integer memory types. Implicit ST inputs are made explicit in the intrinsic operand list, decoded stack-register writes are carried into SSA, and memory reads/writes remain classified.

The processor semantics API models an optional 3-bit TOP and eight physical 2-bit tag classes (`valid`, `zero`, `special`, `empty`); unknown values are represented by empty optionals. Function entry starts unknown. `FNINIT`/`FINIT` and `FNSAVE` establish TOP zero with all slots empty. Decoded stack pushes advance TOP down. A known-empty destination receives a known tag for `FLDZ`, `FLD1`/constant loads, or a `FLD ST(i)` with a known tag; other payloads and possible overflows leave the new tag unknown. Decoded popping forms mark the current physical slot empty and move TOP up on the normal continuation. Explicit ST destinations invalidate their physical tag because arithmetic or a copy may change the class; `FFREE` and `FFREEP` mark the addressed tag empty, with `FFREEP` also advancing TOP. `FINCSTP`/`FDECSTP` rotate TOP without changing tags. `FLDENV` and `FRSTOR` invalidate TOP and every tag because the restored contents are opaque; calls and opaque instructions also clear the abstract state. CFG edges propagate these facts through acyclic blocks; joins retain only facts equal on all paths, and cyclic/unprocessed paths stay unknown. Intrinsic IR carries the known pre-instruction state. When TOP is known, the lifter maps logical ST(i) references to physical registers before SSA. Pops preserve the old physical payload values while marking the popped tag empty; pushes write only the newly exposed physical slot. This keeps remaining values attached to their physical registers across proven TOP rotations. `x87_physical_register` exposes the same logical-to-physical mapping for other consumers. `retire_x87_stack_state` leaves TOP/tag state unchanged when an unmasked supported operation fails to complete or a prior pending exception blocks a waiting instruction.

Reserved subencodings in supported groups are rejected as invalid; a missing byte in a recognized x87 form remains truncated, and the shared parser enforces the architectural 15-byte maximum. Prefix interpretation and address-width behavior remain those of the shared mode rules.

The decompiler represents the arithmetic forms symbolically; it does not execute or evaluate general extended-precision arithmetic. Caller-driven APIs compare canonical 80-bit values and compute FCOM/FUCOM/FCOMI/FUCOMI status effects ([comparison semantics](x87-comparison-semantics.md)), convert binary80 values to signed integers with FIST/FISTP/FISTTP behavior ([integer conversion semantics](x87-integer-conversions.md)), and evaluate FSQRT and FRNDINT rounding for supported finite/special values ([rounding semantics](x87-rounding-semantics.md)). The decompiler carries exact FLD1/FLDZ literals and folds same-block FCHS/FABS; FSQRT folds only when every supported precision and rounding mode gives the same result for a positive normal literal. General x87 comparison folding and FIST-family memory writes are not connected. Pending exception state is caller-owned and only gates stack retirement when a caller invokes the new helper; automatic exception creation for all decoded instructions and stack overflow/underflow remain unsupported. Environment restores intentionally erase state, and joins do not synthesize stack permutations. It also does not claim to decode MMX/SSE/AVX through these escape tables. Legacy NPX control aliases are recognized by encoding; exact processor-generation availability is not modeled. This is an analysis milestone, not a complete emulator or formal ISA oracle.

The caller-driven `evaluate_x87_examine` helper classifies binary80 ST(0) values for FXAM and updates C0/C1/C2/C3 while preserving other FSW bits. It accepts the caller's empty-tag fact and does not mutate TOP/tags or fold from decompiler SSA; see [FXAM semantics](x87-examine-semantics.md). The caller-driven `evaluate_x87_test` helper evaluates FTST as an ordered comparison against positive zero, including FSW relation bits and masked/unmasked invalid behavior; it leaves stack-underflow handling to its caller, as described in [x87 comparison semantics](x87-comparison-semantics.md).

Caller-driven packed-decimal helpers now evaluate the decoded `FBLD m80bcd`
and `FBSTP m80bcd` memory forms. FBLD validates all 18 digit nibbles and
expands valid signed values exactly to binary80; invalid digit encodings return
no guessed value. FBSTP rounds with FCW.RC, reports DE/IE/PE and C1 effects,
checks the signed 18-digit range, and emits the architectural packed-BCD
indefinite for masked invalid inputs. Unmasked exceptions suppress the
destination. Memory access and FBSTP's stack pop remain caller-owned; details
are in [packed BCD semantics](x87-packed-bcd.md).

The decompiler now lifts register-stack transfers as exact 80-bit value operations: `FLD ST(i)` copies the source into the pushed slot, `FST ST(i)` assigns ST(0) to the destination, and `FXCH ST(i)` swaps both payloads in parallel. The physical-register remapper applies the incoming TOP consistently to source and destination registers. FXCH reads/writes the tag word and the optional TOP/tag analysis swaps the two physical tag facts; FST ST(i) copies the source tag fact to the destination. Both record FSW reads/writes for possible stack exceptions; their FSW and tag SSA outputs remain opaque. FLD's push and FSTP's pop continue to update TOP/tag facts. Overflow/underflow exception retirement remains unmodeled. Memory stores and FSTP ST(i) payload outputs retain their existing intrinsic modeling.

The processor semantics API provides caller-driven value selection for all eight FCMOVcc predicates, preserving the exact binary80 payload and EFLAGS. FCMOV decoding now reports FSW read/write effects for possible stack-underflow status updates. The helper's precondition is that both stack operands are non-empty; empty-tag exception/indefinite-result handling remains caller-owned. See [conditional-move semantics](x87-conditional-move.md).

The processor API also exposes `evaluate_x87_sign_operation` for FCHS and
FABS. It toggles or clears only the binary80 sign bit, preserving every
significand and exponent bit, including noncanonical payload encodings. For
the normal nonempty-ST(0) path it sets FSW.C1 to zero, preserves other defined
FSW bits, and marks C0/C2/C3 undefined. The helper does not inspect stack tags
or generate stack-underflow status; the caller must provide a nonempty ST(0).
An invalid operation enum returns no result. These raw-bit and condition-code
rules follow Intel's [FCHS and FABS definitions](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-manual-volume-2a-manual.pdf).

Integer memory stores (`FIST`, `FISTP`, and `FISTTP`) expose FSW read/write
effects for conversion exceptions and status flags. The rounded `FIST` and
`FISTP` forms also read FCW for its rounding-control field; `FISTTP` does not
depend on FCW rounding. Existing width, memory-write, ST(0) input, and optional
stack-pop facts are retained. The decoder reports these architectural
dependencies only; it does not calculate the stored integer or exception
retirement. Numeric conversion remains available through the caller-driven
`evaluate_x87_to_integer` helper described in [integer conversion semantics](x87-integer-conversions.md).

The caller-driven `evaluate_x87_scale` helper truncates ST(1) toward zero,
preserves the significand for in-range normal results, and handles binary80
zero/infinity/NaN classes, pseudo-denormals, denormal exception masks,
gradual underflow, overflow, FCW.RC rounding, and precision-exception
retirement. It reports whether an output value exists and whether the
instruction completed. Stack tags/TOP, stack-fault generation, pending
exception delivery, and committing the value remain caller-owned; see
[FSCALE semantics](x87-fscale-semantics.md).
