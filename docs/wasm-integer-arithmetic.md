# WebAssembly integer arithmetic evaluation

`evaluate_wasm_integer_arithmetic` evaluates decoded i32/i64 `add`, `sub`,
`mul`, signed/unsigned `div`, and signed/unsigned `rem` operations on raw stack
bit patterns. Results wrap at the operation width. Divide-by-zero and signed
division overflow are returned as explicit WebAssembly traps; signed remainder
of the minimum value by negative one returns zero without trapping.

The evaluator validates the operand-free scalar bytecode form and never uses
host signed division for the exceptional minimum/-1 pair. It does not pop or
push stack values, dispatch a trap edge, or execute module code; value sampling
and stack/state changes remain caller-owned.
