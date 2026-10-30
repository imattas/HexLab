# x87 Conditional-Move Semantics

`evaluate_x87_conditional_move` evaluates the value-selection part of the eight
register-stack FCMOVcc forms. It uses the incoming EFLAGS bits directly:

| Condition | Predicate |
| --- | --- |
| FCMOVB / FCMOVNB | CF / !CF |
| FCMOVE / FCMOVNE | ZF / !ZF |
| FCMOVBE / FCMOVNBE | CF or ZF / neither CF nor ZF |
| FCMOVU / FCMOVNU | PF / !PF |

When the predicate is true, the exact 80-bit source payload is selected for
ST(0); otherwise ST(0)'s original payload is retained. No host floating-point
conversion occurs. EFLAGS are preserved. The instruction's ordinary valid
stack execution does not change FSW condition codes or TOP.

Both operands must be non-empty for this helper's contract. The x87 decoder
records FSW read/write effects for FCMOVcc because a source-stack underflow
sets the invalid-operation/stack-fault state and clears C1. The helper does
not model empty-tag underflow, masked indefinite results, or unmasked
exception retirement; callers must handle those using the x87 stack/tag and
pending-exception APIs before applying the value result. The decoder continues
to record the EFLAGS read and the ST(0)/ST(i) value effects.

This is a caller-driven semantic helper, not a decompiler constant-folding
rule. It does not infer whether a path satisfies the predicate.
