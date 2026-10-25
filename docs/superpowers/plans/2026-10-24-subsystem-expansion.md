# Subsystem Expansion Implementation Plan

## Goal

Continue toward the approved full HexLab destination by advancing independent subsystems: remote debugging, managed .NET analysis, PDB type-server resolution, and shared-project collaboration.

## Constraints

- Preserve the approved original C++20 monorepo and wxWidgets desktop architecture.
- Keep the desktop closed while the user is gaming.
- Do not modify the active `libs/decompiler/src/decompiler.cpp` worktree or its associated decompiler docs/tests.
- Keep each workstream within its owning subsystem to reduce shared-file conflicts.
- Do not add or run tests in this wave. Inspect existing tests as design evidence only.
- Do not edit or clean `out/` artifacts.
- Integrate via source review, capability ledger updates, and one serialized Windows Debug `hexlab` build.

## Independent workstreams

1. **Remote debugging** — expand the RSP client/server and backend workflow toward live GDB interoperability, selecting a meaningful protocol or process-control gap from the current implementation.
2. **Managed .NET analysis** — expand the CLR/CIL pipeline across metadata, body interpretation, typed/lifted semantics, and public workflow where necessary; choose a coherent end-to-end missing capability.
3. **PDB type-server resolution** — extend bounded CodeView/PDB namespace resolution, including nested server relationships and the resulting type-reference integration, with identity checks and explicit resource limits.
4. **Shared-project collaboration** — extend local multi-writer proposal refresh beyond same-process tabs so separate HexLab processes can discover and review durable collaboration changes safely.

## Integration

- Review each agent's implementation for scope, error handling, bounds, and support claims.
- Resolve shared API or build integration issues in the primary worktree.
- Update capability evidence without claiming unverified coverage.
- Build only; no tests or desktop launch in this wave.

## Integration record

- Remote debugging now performs bounded binary `X` writes with hex `M` fallback; managed methods resolve and lift `calli` from StandAloneSig metadata; PDB type-server resolution follows bounded nested GUID+age or DBI TSM graphs; shared projects auto-refresh across processes through bounded revision polling.
- Integrated Windows Debug `hexlab` build passed on 2026-10-24. No tests were added or run, and no GUI was opened.
