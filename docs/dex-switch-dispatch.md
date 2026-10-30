# DEX switch target selection

`evaluate_dex_switch_instruction` selects a target for a decoded
`packed-switch` or `sparse-switch` when the validated payload cases are
attached to the instruction. It returns the matching case target; unmatched
keys select the bytecode address immediately after the switch instruction.

The helper validates switch kind, payload displacement, vreg access, and
packed/sparse key ordering. It requires analysis to have validated the payload
first. It does not pop the selector register, update the program counter, or
execute the selected edge.
