# Redundant SSA merge cleanup

`simplify_redundant_phis` returns a new lifted function with proven redundant register and memory merges removed. It handles diamonds, loop-carried identities and mutually recursive phi webs, without changing control flow or moving computation.

For example, a loop with `r.2 = phi(r.1, r.3)` and `r.3 = r.2` carries the same value on every iteration. Both definitions can be replaced by `r.1`. The same proof applies to whole-memory or named-partition phis when the loop does not introduce a different memory state. A loop phi with an arithmetic update, store, unknown call memory output, or any other distinct incoming definition remains explicit.

The pass uses a dependency graph with separate namespaces for each exact register view, whole memory, and each named memory partition. An iterative strongly connected component traversal resolves dependencies before consumers. A component collapses only when all inputs outside the component resolve to one exact value. Multiple distinct external inputs and components with no external value remain unchanged. Register identity assignments participate only when source and destination are the same complete register view and the expression has a matching scalar width. The pass does not propagate copies between different registers or reinterpret types.

Every represented use is updated: phi inputs, expression registers, memory base/index and effective-address expressions, frame-register provenance, whole-memory and partition load versions, instruction memory inputs, intrinsic output formulas, ABI argument snapshots, switch selectors, trap predicates, and implicit x86 stack memory inputs. Nontransparent definitions keep their original versions. A summarized read-only call whose memory input/output versions agree keeps that agreement after rewriting. Loads, stores, calls, intrinsics and their effect classifications remain intact.

The standalone API runs a const preflight before copying the function, validates input SSA, and validates the transformed SSA before returning it. This includes register, whole-memory and partition definition uniqueness, phi predecessor coverage and dominance, using `validate_register_ssa`. Malformed SSA returns its validation error; budget or allocation failures return `resource_limit`. The input is never mutated.

The current budgets are 1,024 blocks, 4,096 CFG edges, 200,000 instructions, 16,384 merge/copy nodes, 65,536 merge inputs, 1,000,000 expression nodes, 1,000,000 auxiliary effect/dispatch facts, and expression depth 128. The graph traversal is iterative. Functions containing unreachable blocks, delay-slot edges/snapshots, or exceptional control-flow timing are returned unchanged because those cases require proofs beyond the ordinary reachable SSA contract. JVM evaluation-stack registers and overlapping AArch64 SIMD views are excluded from register merge candidates. Memory namespaces in otherwise supported functions can still be simplified.

`eliminate_dead_code` applies this pass before its existing fixed-point deletion. If standalone cleanup declines incomplete synthetic IR or reaches its budget, dead-code elimination retains its previous acceptance rules. Its liveness walk also preserves roots referenced only by switch selectors, trap conditions, or stack-frame provenance.

Cross-register copy propagation was considered, but ABI snapshots and physical clobbers require additional proofs. Local-only phi reduction would miss mutually recursive loop phis; the SCC proof covers those cycles without expanding the call model.

No tests were added or run during this change, as instructed for the session. Build verification commands and results are recorded below.

## Build verification (2026-11-02)

Windows MSVC 19.44, from the isolated worktree:

```powershell
cmake -S . -B out/build/ssa-merge-windows -G 'Visual Studio 17 2022' -A x64 -DHEXLAB_BUILD_DESKTOP=OFF -DBUILD_TESTING=OFF -DHEXLAB_ENABLE_PINNED_LLVM_ORACLES=OFF
cmake --build out/build/ssa-merge-windows --config Debug --target hexlab_decompiler --parallel 2
```

Both commands exited 0 and produced `out/build/ssa-merge-windows/bin/Debug/hexlab_decompiler.dll`. Existing dependency and decompiler warnings remain; the build had no errors.

WSL Ubuntu 24.04 uses Clang 18.1.3 and Unix Makefiles because Ninja is not installed. A Linux-only PATH avoids slow inherited Windows-path compiler-tool searches:

```powershell
wsl -d Ubuntu-24.04 -- bash -lc 'env PATH=/home/imattas/.local/bin:/usr/local/bin:/usr/bin:/bin cmake -S /mnt/g/HexLab/.worktrees/decompiler-semantics-nov02 -B /tmp/hexlab-ssa-merge-make-nov02 -G "Unix Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug -DHEXLAB_BUILD_DESKTOP=OFF -DBUILD_TESTING=OFF -DHEXLAB_ENABLE_PINNED_LLVM_ORACLES=OFF'
wsl -d Ubuntu-24.04 -- bash -lc 'env PATH=/home/imattas/.local/bin:/usr/local/bin:/usr/bin:/bin cmake --build /tmp/hexlab-ssa-merge-make-nov02 --target hexlab_decompiler -j2'
```

Both WSL configure and full target build exited 0 and produced `/tmp/hexlab-ssa-merge-make-nov02/lib/libhexlab_decompiler.so`. The new `ssa_phi_cleanup.cpp` translation unit also compiled independently with no diagnostics before the full dependency build completed. Existing warnings in dependency and decompiler sources remain. `git diff --cached --check` passed. No project tests, GitHub CI, or push was performed.
