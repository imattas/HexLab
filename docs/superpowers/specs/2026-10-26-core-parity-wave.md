# Core Parity Expansion

## Goal

Continue building HexLab toward a native reverse-engineering workbench by advancing three independent user-facing capabilities: native pseudocode structuring, PDB type import, and graph navigation/synchronization.

## Current Evidence

- `docs/capabilities.csv` identifies nested SSA joins in loop bodies, unsupported PDB field/type forms, and richer graph cross-view synchronization as remaining gaps.
- Native code and UI remain C++20; desktop remains wxWidgets. The current state is the `feat/foundation` branch at the commit preceding this wave.

## Requirements

1. The native decompiler must recover another bounded, common loop/SSA shape while preserving exact predecessor coverage and retaining conservative fallback for ambiguous control flow.
2. The PDB importer must preserve another common CodeView type/field shape into the project type library, including source provenance and unresolved diagnostics where information is insufficient.
3. The desktop graph must add a concrete cross-view workflow that follows graph focus/selection into the relevant analysis views without changing immutable analysis facts or accepting stale locations.
4. Every change must be bounded, deterministic, documented, and compatible with the current project model.
5. Do not run tests, launch the desktop, or access/clean/build `out/`. Compile affected Windows Debug targets where available.

## Design

Each workstream owns one subsystem and makes its own evidence-based feature choice from the existing capability ledger and source. Workstreams must not edit `docs/capabilities.csv`; integration owns that file. Keep changes isolated in separate worktrees and branches. The root agent reviews, builds, updates evidence, and pushes the integrated branch.

## Out of Scope

This wave does not claim IDA Pro parity. It does not change the C++20/wxWidgets platform choice, introduce new dependencies, execute analyzed input, or weaken the existing bounded/fail-closed analysis model.
