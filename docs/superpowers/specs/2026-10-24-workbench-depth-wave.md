# Workbench depth wave design

## Intent

Continue building a native C++ reverse-engineering workbench with IDA-scale analysis workflows. This wave closes three user-visible gaps: common managed exception filters/faults in CIL control flow, project-level inspection of already-decoded Mach-O LSDA metadata, and an interactive Python console attached to the desktop project.

## Goals

- Model bounded CLR filter execution and fault-only exceptional unwind in the lifted CIL CFG while preserving clause order and explicit incomplete semantics.
- Persist source-tracked Mach-O LSDA/personality metadata with the owning image/project and expose it in the existing Mach-O metadata UI.
- Embed the existing HexLab Python automation API in the wxWidgets desktop as an interactive console bound to the active saved project, with asynchronous execution and bounded output.

## Non-goals and anti-goals

- Do not emulate the full CLR runtime, infer exception types, or silently guess ambiguous EH transitions.
- Do not execute Mach-O personality routines, perform target code, or claim unsupported LSDA encodings are understood.
- Do not run untrusted Python automatically, block the wx event thread, or introduce a second writable project owner that conflicts with the active UI session.
- Keep `out/` untouched. Do not add or run tests in this wave; compile-only verification is required.

## Approaches

- **Managed EH:** a full CLR interpreter would provide runtime fidelity but is out of scope and unsafe to infer from current IR. The bounded CFG approach extends existing synthetic dispatch/finally continuations and treats filter results as explicit CFG values; this is selected because the project already represents EH as typed IR and keeps uncertainty visible.
- **Mach-O LSDA:** recomputing metadata at each view open avoids schema work but loses durable source provenance and costs repeated parsing. The project already retains source image bytes and reconstructs loader metadata on reopen. Reusing those validated source-backed records and showing them in the Mach-O view is selected; a second SQLite cache would duplicate derivable state without improving durability.
- **Python console:** spawning a separate runner cannot safely share unsaved edits and risks competing writable sessions. Embedding CPython and exposing a read-only automation facade for the active project is selected; writes continue through existing UI commands until a transaction-safe bridge is available.

## Constraints

- Retain bounded parsing, cancellation, source provenance, project migration compatibility, and explicit unsupported/malformed statuses.
- Use the existing CPython automation module and APIs; keep Python support optional at configure time.
- UI work must execute Python away from the wx event thread and marshal output/state back through wx events.
- Root owns the shared plan, capability ledger, integrated build, and final review. Subsystems have disjoint code ownership.

## Builder decisions

- Root-selected: the console is read-only for project state in this wave, is shown as a dockable panel, and uses the existing automation query API.
- Root ruling: LSDA/personality records are durable through the source-backed project image and are reconstructed by the normal loader path; do not add a duplicate SQLite cache. The user-facing deliverable is project UI inspection with source spans.
- Root-selected: unsupported CIL filter/fault shapes retain a lossless incomplete fallback rather than fabricating exact CLR behavior.
