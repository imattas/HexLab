# Scalar instruction IR example

This C-only ABI 1.23 module defines two example RISC-V custom-0 encodings at
four-byte-aligned `riscv64/rv64` addresses. `0b 05 06 00` computes
`x10 = x12 + 5` modulo 2^64. `0b 15 06 00` computes `x10 = (x12 <u x13) ? 1 : 0`.
These are extension-defined instructions, not standard RISC-V operations.
The module supplies the exact typed DAG and a parallel register output rather
than asking the host to infer a meaning from the mnemonic. Both the binary and
generated package sidecar require `processor.ir.scalar` v1.23.

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
`decompiler::format_pseudocode`. The expected formulas are `x10 = x12 + 5` and
`x10 = (x12 ULT x13)`; SSA may display version suffixes. See [plugin scalar IR](../../../docs/plugin-scalar-ir.md)
for the complete validation/lifecycle contract and a host-side integration snippet.

The standalone C example Debug target compiled and linked. It has not been
loaded or executed by HexLab and is deliberately not part of the default host
build.
