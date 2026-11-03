# ARM32 stack pointer aliases

A32 and source-profiled Thumb function stack analysis now follows exact entry-SP-relative pointers in general registers through the recovered CFG. Previously only SP and one recognized r7/r11 frame base could identify memory cells; a compiler copying an address to another register lost its stack identity.

For example, after `sub sp, sp, #256; add r0, sp, #16; mov r4, r0; str r1, [r4, #4]`, the store is associated with entry-SP-236, and the pointer definitions retain address-taken provenance for entry-SP-240. If r4 differs at a CFG join or is overwritten by a load, the later access is not assigned a guessed slot.

The producer subset is full-width MOV (including A32 unshifted LSL #0 register operands) and immediate ADD/SUB from SP, the active frame register, or another proven alias. Pointer formation records address-taken slot provenance. Immediate-offset single transfers and LDM/STM IA/IB/DA/DB through aliases recover the same entry-relative slots as direct stack accesses. Temporary-base pre/post-index writeback advances the relation; loading the base register itself destroys it. Incoming AAPCS32 single-transfer reads retain argument classification through these temporary bases.

Relations propagate between blocks only when every reachable predecessor agrees. Unknown definitions, partial/shifted register transforms, indexed writeback, and calls invalidate affected temporary pointers. Calls conservatively discard every temporary alias without requiring a calling-convention or callee-save proof. Conditional A32 instructions and conditional or unresolved Thumb IT instructions join their executed and skipped stack states, so a conditional producer or writeback cannot become an unconditional fact. Accesses still represent possible reads/writes at their source instruction.

The implementation retains the existing flow, slot, and access-provenance budgets, adds only fifteen fixed relation cells per flow state, and changes the function-engine fingerprint so derived stack snapshots are recomputed. No persisted user decisions or project schema change. ARM single-transfer cells now use linear offsets rather than the unrelated 6502 page-stack +/-127-byte constraint.

Limitations: no heap/pointer dereference chasing, pointer values spilled and reloaded from memory, dynamic register-indexed stack addresses, register-valued arithmetic, interprocedural alias proof, or complete ABI variable typing. General aliases do not add new SP restoration patterns. Linear alias arithmetic outside signed 32-bit displacement range is discarded; this does not establish an absolute stack-address wrap proof.

Validation: isolated Windows MSVC Debug `hexlab_analysis` build passed. WSL Ubuntu-24.04 Clang 18 compiled the final `stack.cpp` to an object successfully; the full Linux analysis-target build remained in progress at handoff. No tests were added or run, as requested.
