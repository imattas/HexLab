# PE Live-Context Unwinding Design

## Goal

Evaluate validated AMD64 and ARM64 PE unwind metadata against a supplied stopped-thread register context and memory reader, returning a caller register context or a precise bounded error. This advances HexLab from recording PE unwind metadata to using it for stack traces and debugger navigation.

## Existing interfaces

`PeMetadata` in `libs/image/include/hexlab/image/pe_metadata.hpp` contains `exception_functions` with normalized AMD64 `PeUnwindInfo` and `arm64_exception_functions` with packed/xdata ARM64 records. The debugger exposes registers as named byte arrays and bounded memory reads, but the unwinder must remain independent of the debugger module and OS backend.

## Design

Add an image-level API in `hexlab/image/pe_unwind.hpp`. `PeRegisterContext` contains a `std::map<std::string, std::vector<std::byte>>` of named registers. `PeMemoryReader` is a callback returning `Result<std::vector<std::byte>>`. `unwind_pe_frame(metadata, architecture, module_base, instruction_pointer, context, memory)` resolves the containing runtime function using the module-relative PC and produces a copied caller context. It does not mutate the input. Register names are canonical lowercase architecture names (`rax`, `rbx`, `xmm6`, `x0`..`x30`, `sp`, `fp`, `lr`, `pc`); register byte order is little-endian for PE targets.

AMD64 applies all operations represented by the current normalized `UNWIND_INFO` model, supports chained unwind records with a strict depth bound, and handles machine-frame records only when the required memory is readable. ARM64 supports packed canonical forms and the decoded xdata opcode families, including scalar/vector saves, SVE Z/P registers and `alloc_z` when the caller supplies the runtime vector length. Pointer-authenticated returns remain explicitly unsupported when keys are absent. The live PC selects the active prolog/epilog state where metadata supports it; otherwise the function body state is used. The return PC and caller SP are set only after every read and validation succeeds.

All address arithmetic is checked, each memory request is bounded to the exact scalar/vector register width needed, excessive chain/code counts fail with `resource_limit`, short reads fail with `out_of_bounds`, missing registers fail with `invalid_argument`, and unknown/reserved operation encodings fail with `unsupported` or `malformed`. No arbitrary target memory scanning is permitted.

## Tests

Construct metadata directly for deterministic AMD64 and ARM64 tests. Cover ABI register naming/widths, stack arithmetic and return-address recovery, AMD64 chained records and frame-register paths, ARM64 packed and xdata forms, unreadable/short memory, address overflow, unsupported opcode, missing registers, and input-context immutability. Loader-produced metadata continues to be covered by the existing PE exception suite.

## Boundaries

This change does not add UI controls, walk multiple frames, execute language handlers, interpret PDB scopes, or change debugger APIs. The caller is responsible for supplying a coherent stopped-thread snapshot and resolving module identity/base. Image library owns the generic callback-based evaluation API.
