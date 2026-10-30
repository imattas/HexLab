# Concrete A32 and Thumb NZCV evaluation

`arm32_semantics.hpp` exposes a caller-driven 32-bit evaluator for decoded,
flag-setting A32 and Thumb data-processing instructions. The caller supplies
the incoming NZCV bits and a register-value callback; the evaluator returns
the computed ALU value, concrete resulting flags, the exact flag write mask,
and whether the instruction writes a general-purpose destination. It never
reads image memory or changes machine state.

Supported operations are AND, EOR, SUB, RSB, ADD, ADC, SBC, RSC, TST, TEQ,
CMP, CMN, ORR, MOV, BIC, and MVN. ADC/SBC/RSC consume incoming C as carry or
no-borrow input. Addition carry and subtraction no-borrow are computed at
32 bits; V is computed from the corresponding signed 32-bit operation,
including carry/borrow input. TST/TEQ/CMP/CMN return their ALU result for
inspection but report `writes_result=false`.

The decoded adapter resolves immediate, plain-register, and
`ArmShiftedRegisterOperand` forms. It implements LSL/LSR/ASR/ROR immediate and
register amounts, RRX, and the architectural carry-out rules, including
register shift amounts of 0, 32, above 32, and ROR multiples of 32. Logical
operations update N/Z and update C only when the decoded shifter produces a
carry result; otherwise C is preserved. V is preserved for logical operations.
Arithmetic and compare/test operations update all four flags. The decoder's
flag-write mask is retained for partial logical updates; a caller-resolvable
register-specified shift supplies its runtime C result even though static
decode cannot know that flag value.

The adapter accepts only A32/Thumb instructions whose decoded operand shape,
flag metadata, and runtime input values match this subset. It rejects
flag-unknown forms other than logical register-specified shifts, PC writes,
multiply, memory operands, unsupported opcodes, missing source values, and
unmodeled shifter forms. Conditional execution is not applied: the caller
decides whether the instruction executes and supplies the incoming flags for
an executed instruction. This API does not model APSR side effects outside
NZCV, exceptions, or a multi-instruction register/flag state.

`evaluate_arm32_condition` computes the architectural EQ/NE, carry, sign,
overflow, HI/LS, and GE/LT/GT/LE predicates from concrete NZCV values; AL
returns true and condition 15 fails closed. The decoded
`evaluate_arm32_instruction_predicate` applies A32 or Thumb predicate metadata,
including an active Thumb IT condition. It returns no result when the Thumb IT
state is unknown, and only reports whether the instruction is enabled: it does
not execute the instruction, select a branch target, or update PC or NZCV.
