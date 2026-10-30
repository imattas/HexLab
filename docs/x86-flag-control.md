# x86 flag-control instructions

The scalar x86 decoder recognizes `CLI` (`FA`) and `STI` (`FB`) in 16-, 32-,
and 64-bit modes. Both use the shared `x86_flag_control` opcode and retain
their mnemonic. Their instruction metadata reads and writes FLAGS.

`evaluate_x86_flag_control_instruction` clears IF (bit 9) for `CLI` and sets
IF for `STI`, preserving every other FLAGS bit within the decoded flags width.
The evaluator models the requested bit update only; it does not check CPL,
IOPL, virtualization controls, or whether the instruction is permitted in the
current execution context. It also does not model `STI`'s one-instruction
interrupt shadow or delivery of pending interrupts.
