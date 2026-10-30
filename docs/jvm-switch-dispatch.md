# JVM switch target selection

`evaluate_jvm_switch_instruction` selects the target for a decoded
`tableswitch` or `lookupswitch` given the operand-stack int key. Dense table
keys are interpreted from the first encoded case value; sparse keys use the
decoded strictly increasing key/target pairs. Unmatched keys select the
decoded default target.

The helper validates the switch kind, dispatch flow, default-target agreement,
and case-key layout. It returns an address but does not pop the operand stack,
change the program counter, or execute the selected control-flow edge.
