# Scalar instruction IR example

This C-only ABI 1.22 module defines one example RISC-V custom-0 encoding:
`0b 05 06 00`, at a four-byte-aligned address in `riscv64/rv64`, computes
`x10 = x12 + 5` modulo 2^64. It is an extension-defined instruction, not a
standard RISC-V operation. The module supplies the exact register/constant
DAG and a parallel register output rather than asking the host to infer a
meaning from its mnemonic. Both the binary and generated package sidecar
require `processor.ir.scalar` v1.22.

Build this standalone example against an installed SDK:

```powershell
cmake -S examples/plugins/scalar-ir -B build/scalar-ir -DCMAKE_PREFIX_PATH=<HexLab-install>
cmake --build build/scalar-ir --config Debug
cmake --install build/scalar-ir --config Debug --prefix <plugin-install>
```

The host selects this module through the ordinary PluginManager lifecycle.
Recover a keyed function snapshot using `manager.analysis_options(options)`,
then call `plugins::lift_function_with_extensions(manager, function, snapshot,
options)` and pass the returned common IR through `decompiler::to_ssa` and
`decompiler::format_pseudocode`. The expected register formula is `x10 = x12 + 5`;
SSA may display version suffixes. See [plugin scalar IR](../../../docs/plugin-scalar-ir.md)
for the complete validation/lifecycle contract and a host-side integration snippet.

The example has source-review evidence only; it has not been built or executed
as part of this change. It is deliberately not part of the default host build.
