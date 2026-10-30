# WebAssembly memory page operations

`evaluate_wasm_memory_pages_instruction` evaluates MVP `memory.size` and
`memory.grow` for a WebAssembly32 memory. It validates the decoded zero memory
index and page-state bounds. `memory.size` returns the current page count.
`memory.grow` returns the old page count on success and updates `pages_after`;
if the requested delta exceeds the caller-supplied maximum, it returns
`UINT32_MAX`, preserves the old size, and marks `growth_failed` without a trap.

The helper enforces the WebAssembly32 ceiling of 65,536 64-KiB pages. The
caller supplies the effective memory maximum and performs the actual allocation
or commits the page count; resource exhaustion and runtime memory ownership
remain outside the evaluator.
