# Source variable and type recovery across SSA and stack aliases

Date: 2026-10-22

## Design

HexLab currently models machine state as versioned registers and coarse memory SSA. The type pass already infers widths, signedness, pointer evidence, fields, and candidate ABI prototypes; stack naming only recognizes negative constant offsets through an unchanged frame register. The next source-recovery step should preserve those machine facts while exposing stable source-level identities to the decompiler and the Variables view.

A recovered variable is keyed by its origin class and canonical location: an SSA register value (physical register plus version, with version zero representing the incoming value), or a proven stack byte range normalized to a function frame base. Names are deterministic and collision-free (`argN`, register-derived value names, and `local_<offset>`). A variable's type is taken from existing type propagation or from the exact stack access widths. ABI parameters and returns are attached only when the configured ABI identifies the observed location; gaps and conflicting evidence remain unknown and diagnosed.

Stack normalization follows register copies and constant add/sub assignments back to a recognized frame register or the incoming stack pointer. Each alias must have a unique displacement. Conflicting paths, dynamic arithmetic, overflow, indexed accesses, overlapping byte ranges, and unsupported widths are not named. Escaped local addresses are treated as alias escapes: their address is recorded, but the local remains a typed addressable object only if all observed accesses agree on one canonical slot and range. Passing an unresolved pointer to a call prevents assuming a unique local alias.

Recovery is observational and does not mutate machine semantics, memory SSA, or source debug data. Existing pseudocode stack names continue to use the same canonical identity; ABI and variable definitions are returned as metadata for clients to render consistently. The desktop pseudocode view presents stack locals with recovered types and first access addresses, plus ABI parameters at function entry.

## Implementation plan

1. [x] Add stable names and origin/location metadata to `TypeRecoveryResult` variables, including typed stack-local records and ABI argument identity.
2. [x] Share a checked constant-alias resolver between ABI stack-argument inference and stack-local recovery. Reject inconsistent cycles and arithmetic overflow.
3. [x] Extend stack slot recovery from direct frame-pointer operands to unique constant aliases of recognized frame/stack registers, preserving overlap and dynamic-address conservatism.
4. [x] Add cross-block alias, phi ambiguity, escaped-address, overlapping-range, malformed expression, and ABI-location tests.
5. [x] Update the decompiler type-recovery and stack-variable docs. Build and run decompiler tests in an isolated build directory; leave CMake and UI integration to the root agent. (Compile-only checks have passed; linked tests are pending the in-flight processor integration.)
6. [x] Integrate recovered stack-local names/types and ABI `argN` variables into the desktop pseudocode view without changing shared CMake or the type-symbols view.

## Validation

Validation completed in isolated Visual Studio builds: 10/10 selected decompiler tests passed in `.agent-source-recovery-vs2`; `desktop_pseudocode` and `decompiler_type_recovery` passed 2/2 in `.agent-source-recovery-desktop-red`. The desktop GUI test requires that build's wxWidgets runtime directory be prepended to `PATH`. Shared CMake, capability matrices, reference matrices, processor files, loader files, and `type_symbols_view` were not changed by this workstream.
