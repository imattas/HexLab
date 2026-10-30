# DEX floating comparisons

`evaluate_dex_float_compare_instruction` evaluates decoded `cmpl-float`, `cmpg-float`, `cmpl-double`, and `cmpg-double` from raw IEEE-754 operand bits. It returns -1, 0, or +1 as a signed 32-bit DEX integer. For any NaN operand, `cmpl` returns -1 and `cmpg` returns +1. Positive and negative zero compare equal; all other values follow IEEE numeric ordering.

The helper classifies NaNs and compares ordered values from their bit patterns without host floating-point operations. It validates the decoded instruction, destination/source widths, and wide-register slot effects. Callers provide values from the DEX register file and commit the integer result. `cmp-long`, floating arithmetic, and conversion semantics are not part of this helper.
