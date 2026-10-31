# Windows and Linux Host Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove macOS as a supported HexLab host while retaining Windows and Linux builds and Apple-target binary analysis.

**Architecture:** Gate CMake to Windows/Linux, remove macOS build presets, CI and packaging, then update current support claims and debugger host surfaces. Keep Mach-O parsing and other Apple-target analysis independent of host OS support.

**Tech Stack:** C++20, CMake 3.24, wxWidgets, GitHub Actions, Markdown.

**Spec:** `docs/superpowers/specs/2026-10-31-windows-linux-host-support.md`

## Global Constraints

- Windows and Linux are the only supported host operating systems.
- Apple-target executable formats and processor profiles remain supported analysis inputs.
- Do not add or run tests unless specifically requested.

## Review Focus

- Linux still receives ELF RPATH, shared-library PIC, debugger, and CPack behavior.
- Windows runtime dependency collection and ZIP distribution remain intact.
- Mach-O parsing and Macintosh encodings remain available on supported hosts.
- No current docs or CI claim macOS host support.

---

### Task 1: Enforce supported hosts in CMake

**Files:** `CMakeLists.txt`, `CMakePresets.json`, `cmake/HexLabLibrary.cmake`, `cmake/SQLite.cmake`, `apps/cli/CMakeLists.txt`, `apps/desktop/CMakeLists.txt`, `apps/debug-server/CMakeLists.txt`

- [x] Reject hosts other than Windows and Linux before dependency configuration.
- [x] Remove macOS install-name, AppleClang compatibility, universal-binary and app-bundle packaging branches while preserving Linux `$ORIGIN` behavior.
- [x] Remove macOS configure/build/test presets and keep both supported host preset families.

### Task 2: Remove macOS CI and packaging

**Files:** `.github/workflows/portability.yml`, `packaging/macos/create_app_bundle.py`

- [x] Keep Linux Clang/GCC and desktop CI jobs; remove macOS runners and Apple-specific packaging checks.
- [x] Remove the macOS app-bundle packaging script.

### Task 3: Align support documentation and capability inventory

**Files:** `README.md`, `CHANGELOG.md`, `docs/building.md`, `docs/unix-distribution.md`, `docs/package-manifest.md`, debugger support docs, `docs/plugin-sdk.md`, `docs/capabilities.csv`, project design spec.

- [x] State Windows/Linux host support and remove current macOS package, debugger, plugin path, and CI claims.
- [x] Preserve historical notes and Apple-target file-format/processor analysis claims.

### Task 4: Review changes

- [x] Inspect diffs for accidental removal of Mach-O analysis or Linux behavior.
- [x] Run `git diff --check` and list CMake presets; do not run tests.
