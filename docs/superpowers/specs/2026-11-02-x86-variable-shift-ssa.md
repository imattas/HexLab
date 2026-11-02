# x86 variable-count shift SSA results

For decoded x86/x64 register-destination `SHL`, `SHR`, and `SAR` whose count is a register, lift the result into typed bit-vector SSA rather than leaving the destination without an explicit value. Mask the count to five bits for 8/16/32-bit destinations and six bits for 64-bit destinations. An effective count of zero preserves both destination and status flags. Nonzero counts below the width use the corresponding shift; a count equal to the width yields zero for `SHL`/`SHR` and sign-fill for `SAR`. Counts above the width remain undefined, matching the existing scalar evaluator contract.

Variable-count status flags after a nonzero shift remain opaque in this slice. Memory destinations, rotates and rotate-through-carry remain intrinsics. No memory access or processor execution is introduced.
