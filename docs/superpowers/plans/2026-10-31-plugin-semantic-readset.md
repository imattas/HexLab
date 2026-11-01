# Plugin Semantic Read-Set Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let native processor extensions declare bounded semantic-decoder external inputs so HexLab can safely fingerprint and reuse their analysis results.

**Architecture:** Add an optional append-only ABI 1.36 read-set callback to `HexLabProcessorExtension`. The callback writes into host-owned, bounded buffers; the plugin manager validates and copies every extension's declarations into `AnalysisOptions::semantic_decoder_read_set`, qualifying identities by plugin and extension. Missing, failing, malformed, or over-limit declarations remain uncertified and preserve the existing conservative full-reanalysis behavior.

**Tech Stack:** C++20, append-only C ABI, CMake/MSBuild, Markdown.

**Spec:** `docs/incremental-metadata-invalidation.md` and `docs/plugin-sdk.md`.

## Global Constraints

- Preserve binary compatibility for older extension descriptor prefixes with `struct_size` checks.
- Keep existing global analysis limits; plugin callback output has stricter per-extension limits.
- External-input digests are caller supplied and must change when content changes.
- Do not add or run tests unless the user asks; use focused compilation and static validation.
- Do not edit `out/` or push.

## Review Focus

- Old descriptors with no callback remain loadable and uncertified.
- Callback failure, throw, duplicate identity, empty/NUL identity, zero digest, bad extent, and capacity overflow all fail closed.
- The host owns all copied strings, digests, and ranges after the callback returns.
- Multiple plugins cannot collide by returning the same extension-local identity.
- An empty successful read set explicitly certifies no extra inputs.

### Task 1: Append the bounded C ABI callback

**Files:** `libs/plugins/include/hexlab/plugins/plugin_abi.h`

- [x] Add fixed-layout input-digest and read-set output structures with host-supplied capacities and buffers.
- [x] Append the optional callback after the current `HexLabProcessorExtension` tail and advance ABI minor to 36.
- [x] Keep old extension struct-size prefixes valid.

### Task 2: Validate and aggregate plugin manifests

**Files:** `libs/plugins/include/hexlab/plugins/plugins.hpp`, `libs/plugins/src/plugins.cpp`

- [x] Retain the callback only when the descriptor size covers the new tail.
- [x] Invoke each active processor extension under existing manager synchronization and copy its results immediately.
- [x] Enforce bounded counts, identity syntax/length, nonzero SHA-256, range validity, and cross-extension identity uniqueness.
- [x] Install the aggregate provider as `AnalysisOptions::semantic_decoder_read_set`; throw on any uncertified source so existing analysis logic disables reuse.

### Task 3: Document the contract and evidence

**Files:** `docs/plugin-sdk.md`, `docs/incremental-metadata-invalidation.md`, `docs/capabilities.csv`

- [x] Document limits, callback return values, ownership/lifetime, identity prefixing, and fail-closed behavior.
- [x] Record the new SDK surface while keeping its capability partial.

### Task 4: Focused verification

- [x] Run `git diff --check` and parse the capability CSV.
- [x] Compile the changed plugin manager and the existing plugin example targets; do not run tests.
- [x] Review the diff for ABI tail placement and no unsafe certification fallback.
