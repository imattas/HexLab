# Segmented analysis validation

Stage 4b adds explicit 386 segment coordinates, bounded profile import, per-address decoding context, typed far operands and domain-aware analysis/navigation. This is one stage of the larger IDA-class suite; it does not establish full feature parity.

Logical, linear and physical coordinates remain distinct. Aliases preserve annotation identity while sharing canonical patches. Code, address, operand and stack widths remain independent. Embedded recipe v2 preserves the older flat recipe bytes and project schema 1. Derived cache v3 validates context, domain tables and mapping fingerprints; genuine older v1/v2 payloads recompute without rewriting user history.

Source acceptance: headless Debug and Release each passed 57/57 tests; desktop Debug passed 69/69. Logs are `out/segments-task7-full-{headless,release,desktop}.log`. Ten repeated full native segmented workflows passed in `out/segments-task7-native-workflow-repeat.log`. Own-window normal, graph and compact captures were inspected under `out/build/windows-desktop/tests/artifacts/x86-segment-*.png`.

Authored execution fixtures compare 24 Bochs cases and 14 QEMU cases with pinned test-only tools, bounded records, deadlines and negative-contract checks. Existing native Win32/x64 CPU canaries remain included. These checks do not execute arbitrary user inputs or establish full 386 semantics. Tool provenance and limitations live beside `tests/fixtures/x86_16_oracle`.

Delivery checks passed on Windows x64 with MSVC 19.44:

- Fresh disconnected headless Debug: 57/57, `out/segments-task8-offline-tests.log`; no dependency-fetch directory.
- Fresh `BUILD_TESTING=OFF` Release: `out/segments-task8-production-build.log`. All eight runtime DLLs passed import/export checks in `out/segments-task8-production-boundary.log`: engines remain wx-free, with no emulator dependency or private testing exports. Public database checkpoint methods are ordinary production APIs.
- Final desktop rerun: 69/69, `out/segments-task8-final-desktop.log`.
- Complete developer bundle: `out/install/SegmentedDebug`, checked by `tests/install_tests.cmake`, `tests/project_install_tests.cmake` and `tests/segmented_install_tests.cmake`. CLI/profile/history/export, native segmented workflow, genuine cache compatibility and authored CPU comparisons pass through installed runtimes. Validation executables are copied without engine DLLs; emulators remain outside the distribution under `out/tools`.
- Actual packaged application launches in 16/32/64 modes validate each engine/wx module path and capture only its own window. Normal and 800x600 real16 views show selector-labelled listing, functions and selected mode. The command-line project-launch regression was observed, fixed, and rerun successfully in `out/segments-task8-startup-green.log`.
- A standalone SDK consumer under `tests/sdk/segmented` compiles against installed public headers/import libraries and validates profiles, aliases, decoding, recovery, a consumer graph callback across the DLL boundary, and actual installed module paths. Result: `out/segments-task8-sdk.log`.

The Debug bundle is a developer/test distribution and includes instrumented engines used by private validation executables. The separate production Release build proves test-hook exclusion; a redistributable end-user release is not claimed here. Prior ProjectAnalysisDebug and X86ModeDebug installations are preserved.

The package inventory records 113 runtime/SDK/documentation artifacts: 13 binaries, eight import libraries, 65 headers and 27 documentation/license files. Per-file SHA-256 and byte sizes are in `out/segments-task8-package-inventory.json`; validation fixtures and tools are recorded separately from that runtime inventory.

One fresh independent read-only whole-stage review found no Critical, Important or actionable Minor issues. It covered translation boundaries, multi-domain identity, profile persistence, decoder/far flow, recovery/cache validation, workspace operations and frontend opening. It inspected desktop and SDK result logs but did not independently build or run tests. The review is archived with the stage ledger. Stage 4b is accepted with these limits; full-ISA, privilege transitions, remaining loaders/platforms and the broader application remain ongoing work.
