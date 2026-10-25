# Native Workbench Expansion Wave

## Intent

Continue building HexLab toward an IDA-class reverse-engineering workbench by advancing the symbol, debugger, and desktop-inspection paths in one independently owned slice each. The goal is reviewable source-level progress across distinct major subsystems, with explicit bounds and conservative handling of unsupported data.

## Current evidence

- The Objective-C scanner already returns bounded class, metaclass, category, protocol, method, property, and ivar records, and the CLI exposes them. The desktop has no Objective-C-specific view.
- The C++ symbol presenter supports ordinary MSVC functions, templates, operators, constructors/destructors/conversion operators, but unknown special names retain raw text. Special-name presentations are not required for symbol identity.
- The Linux ptrace backend has multi-thread continue schedules on x86; AArch64 native register/debug support exists, but multi-thread scheduling remains a documented gap. Darwin remains single-thread execution.

## Approaches

1. Continue three isolated parser additions. This has low integration risk but little user-visible workflow progress.
2. Deliver one vertical slice in the desktop, symbol pipeline, and debugger while retaining current subsystem APIs. **Selected** because it improves three separate IDA-class workflows without a shared API migration.
3. Replace the shared project, image, or debugger model first. This is not justified: existing APIs already expose the metadata, ABI result, and per-thread schedule needed for these slices.

## Goals

- Let desktop users inspect validated Objective-C runtime records and navigate to their source addresses.
- Render additional well-understood Microsoft ABI special names while preserving raw names for unsupported or malformed inputs.
- Permit safe multi-thread Linux AArch64 resume schedules with event ownership and stop-and-rollback behavior equivalent to the established Linux x86 contract.

## Constraints and non-goals

- Keep the Objective-C scanner's existing budgets and record statuses; do not rescan or infer runtime-only relationships in the view.
- Never use demangled spellings as symbol identity; malformed, ambiguous, or unrecognized MSVC encodings remain unchanged.
- Do not report a Linux thread schedule as atomic. Reject unsupported step/breakpoint/signal combinations before resuming any thread; contain partial resume failures by interrupting and waiting for already resumed peers.
- Keep each workstream in its assigned source/doc files. Root owns cross-cutting capability-ledger updates and integration review.
- Do not add or run tests. Compile relevant Debug targets where supported. Keep the GUI closed and leave `out/` untouched.

## Builder decisions

- The Objective-C page belongs in the existing Binary Metadata notebook, uses the already produced scan snapshot, and exposes explicit navigation callbacks.
- MSVC support is additive to the current bounded parser; use the Microsoft decorated-name ABI grammar as the authority and keep unsupported cases conservative.
- AArch64 scheduling follows the backend's existing stop-and-rollback model. The implementation must preserve pending event ownership and defer racing stops rather than attributing them to the wrong thread.
