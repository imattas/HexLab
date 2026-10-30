# Capability Inventory Completion Plan

> **For agentic workers:** Use the repository's established subsystem patterns; keep each verified feature bounded and evidence-backed.

**Goal:** Close every capability currently marked `partial` in `docs/capabilities.csv` by implementing its stated remaining work, integrating it, and recording verifiable evidence.

**Architecture:** Treat the capability CSV as the authoritative queue. Partition work by independent subsystem ownership (processors; loaders/recognition; analysis/decompilation; and the remaining desktop, debugging, automation, projects, and delivery work). Each capability remains partial until its stated next-stage gaps are actually addressed; do not relabel a bounded slice as complete.

**Tech Stack:** C++20, CMake, wxWidgets, project libraries, capability CSV and subsystem docs.

**Spec:** `docs/capabilities.csv`, each row's `capability`, `variant`, `evidence`, and `next_stage` fields.

## Global Constraints

- Current inventory has 89 `partial` rows; recount before and after each work wave.
- Preserve the multi-target monorepo architecture and use existing subsystem APIs.
- Keep local commits only; do not push to GitHub.
- Never stage or modify `.build/` artifacts.
- Do not claim a capability is complete while its stated gaps remain.
- Use builds and diff checks for integration evidence; do not add or run tests unless explicitly requested.

## Review Focus

- Capability labels must match actual behavior and documented limits.
- Existing persisted project data and old schema compatibility must remain intact.
- Malformed or adversarial input must not escape existing size/work bounds.
- UI state changes must be scoped to the correct document/project and handle read-only projects.
- Cross-platform changes must not silently regress Windows builds.

## Work queue

- [ ] Processors: close each of the 14 partial processor capabilities, prioritizing bounded ISA-family gaps and integration.
- [ ] Loaders and recognition: close binary format, archive, managed, firmware, and signature gaps.
- [ ] Analysis and decompilation: close decoder-connected semantics, recovery, data flow, structuring, and native/managed decompilation gaps.
- [ ] Desktop and search/editing: close persisted issue triage, navigation, plugin, context, source, and editing gaps.
- [ ] Debugging and automation: close backend, thread-control, SDK, Python and extension gaps.
- [ ] Projects and delivery: close reliability, exchange/collaboration, platform build, packaging, performance and accessibility gaps.
- [ ] Reconcile all 89 rows against implementation evidence and rebuild supported configurations.
