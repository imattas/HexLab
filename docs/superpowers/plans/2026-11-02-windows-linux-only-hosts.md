# Windows and Linux Host Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove dormant macOS host debugger code and keep HexLab host support explicit for Windows and Linux.

**Architecture:** Keep the existing CMake Windows/Linux host gate and debugger backend selection. Remove the unreferenced Darwin backend and debugger-specific documentation, while retaining Mach-O parsing and analysis as input features on Windows/Linux.

**Tech Stack:** C++20, CMake, Markdown, CSV.

**Spec:** `docs/superpowers/specs/2026-11-02-windows-linux-only-hosts.md`

## Global Constraints

- Supported hosts are Windows and Linux only.
- Apple-target formats remain analysis inputs on supported hosts.
- Do not modify third-party platform support.
- Do not run tests.

## Review Focus

- Windows and Linux backend selection remains intact; verify CMake source references.
- No current documentation claims a supported Darwin debugger; search tracked docs.
- Mach-O analysis documentation remains intact.

---

## Task 1: Remove dormant Darwin debugger implementation

**Files:** delete `libs/debugger/src/native_backend_macos.cpp` and the unreferenced `libs/debugger/src/darwin_modules.hpp`; update `docs/capabilities.csv` to mark the implementation as removed. Keep the Darwin debugger notes only as historical, unsupported documentation.

- [x] Confirm CMake selects only Windows, Linux, or portable stub backends.
- [x] Delete the unused Darwin implementation and helper; retain docs that clearly say the backend is unsupported history.
- [x] Update the capability ledger's current debugger platform description and preserve the implementation details as historical evidence.
- [x] Verify there are no dangling source/document links and inspect `git diff --check`; Windows desktop/CLI and WSL Linux CLI builds pass with tests disabled.
