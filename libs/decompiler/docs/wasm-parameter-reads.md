# WebAssembly typed parameter reads

The Wasm scalar lifter can read function parameters through `local.get` when
the loaded module provides the function signature. Parameter value types are
retained in `WasmMetadata`, checked against the local index, and emitted as
typed source variables. A matching name-section entry supplies the variable
name; otherwise the lifter uses `argN`.

The supported subset is intentionally narrow. `local.set`, `local.tee`,
declared locals, globals, calls, and stack effects that depend on those
operations still fail closed. In particular, a local index that points beyond
the function's parameter list is not mistaken for a parameter. This avoids
inventing local values or assignments without local-variable dataflow.

The two-argument `lift_wasm_function` overload has no module metadata and
therefore cannot lift `local.get`. The CLI and desktop pseudocode paths pass
loaded module metadata and can recover typed parameter reads.
