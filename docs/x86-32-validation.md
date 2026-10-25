# x86-32 validation

This subproject extends HexLab's original scalar decoder and shared project
services to flat little-endian x86-32. It does not establish complete x86 ISA
coverage or IDA feature parity. x86-16 execution/segmentation, other executable
formats/processors, types, decompilation and debugging remain required later work.

## Implemented behavior

Raw CLI and native wx mapping choices support x86-32 and x86-64. PE headers select
their effective mode. Processor capabilities and every production decode path use
the image's explicit architecture, execution mode and byte order. Invalid pairs,
unsupported modes and non-little-endian x86 contexts fail closed. Existing x64 raw
recipe bytes and the native dialog's x64 default are preserved.

The scalar subset includes legacy INC/DEC opcode bytes, 16/32-bit operands,
16/32-bit addressing, retained segment expressions, selected scalar arithmetic,
stack and near-control forms. [Instruction coverage](x86-32-coverage.csv) lists
the limits. Unknown forms stop explicitly; they do not acquire invented lengths.

Shared recovery, ownership, references, graphs, manual listing and code decisions
dispatch by loaded mode. Immediate search retains encoded and effective widths.
Raw32 mappings enforce the 32-bit address ceiling, including empty inputs; entry
validation retains address-space and initialized mapping constraints.

Derived cache v2 carries authoritative processor context in its envelope and
typed instruction records, including hidden relative-target and stack widths.
Loading checks actual effective bytes with the matching original decoder and
rebuilds rooted ownership, references and strings. Checksum-recomputed wrong-mode
payloads are rejected. Genuine old v1 cache bytes recompute without changing
user history or migrating the current v2 user schema. Read-only stores are not
repaired.

## Evidence collected

- `processor_modes` and `x86_32_decoder`: literal typed records, all truncation
  boundaries for known fixtures, mode confusion, prefix/length bounds and the
  complete first-opcode/ModRM envelope sweep. The sweep proves bounded behavior
  and mode invariants; it is not an independent semantic oracle.
- `mode_project`: calls, loops, shared ownership, partial frontiers, manual data,
  cancellation and short reads; typed absolute/BX+SI references; cache roundtrip;
  same-mode reuse; effective PE64-to-PE32 header edits with annotations and
  undo/redo. Unannounced mode changes reject reuse.
- `raw_modes`, `cli_binary`, `project_cli`: raw mode and address limits, literal
  canonical recipes, original x64 recipe identity, source-missing read-only
  reopen, signed-immediate search and exact patched exports.
- `desktop_mode`: real native choice and coordinate errors, simultaneous 32/64
  tabs for the same bytes, active mode labels, nonfirst search/reference/graph
  navigation, name/comment editing, Save As, patch/undo/redo/export and actual
  read-only reopen after closing the writer. A held legacy worker result must
  leave the active long-mode tab's facts and selection unchanged.
- Complete Debug headless 43/43 and desktop 54/54 before the new execution oracle:
  `out/x86-raw-final-{headless,desktop}.log`. After oracle integration, full Debug
  desktop 55/55: `out/x86-integrated-desktop.log`.

## Independent native execution

The separate project `tests/fixtures/x86_32_oracle` is compiled with MSVC's Win32
toolchain. `_M_IX86`, a four-byte pointer assertion and the PE `14C machine (x86)`
header verify its architecture. No Win32 objects are linked into x64 HexLab.
The CTest controller starts this executable as a separate process, then passes
its measurements to the x64 original-decoder checker.

Nine authored probes cover INC32, DEC32, INC16, AH INC, wrapped BX+SI LEA, a SIB
LEA, PUSH32, PUSH16 and POP16. Measurements include selected CF/ZF/OF/SF behavior,
register values and actual stack-slot bytes/deltas. LEA does not dereference
synthetic addresses; stack changes and callee-saved registers are restored.
There is no arbitrary-input execution facility.

The native and existing x64 execution tests pass together, with 51 new assertions:
`out/x86-native-oracle-integrated.log` and `out/x86-native-oracle-desktop.log`.
Changing the measured LEA result fails the checker; a missing oracle fails the
test instead of skipping it. These negative controls are recorded in
`out/x86-native-oracle-negative.log` and `out/x86-native-oracle-missing.log`.

Verified host: Windows NT 10.0.26300 x64; MSVC 19.44.35229, toolset 14.44.35207,
Windows SDK 10.0.26100. These are representative execution checks, not proof of
every instruction form. Native near16/far transfers, segmentation and vector
execution are outside this oracle's coverage.

## Delivery evidence and review status

Full Debug and Release headless suites passed 44/44 in
`out/x86-integrated-debug-release.log`. After preserving mode labels during
navigation, the complete desktop suite again passed 55/55 in
`out/x86-install-validation.log`. Fresh disconnected headless tests passed 44/44
in `out/x86-offline-validation.log`. The fresh `BUILD_TESTING=OFF` Release build
and production CLI workflows passed in `out/x86-production-validation.log` and
`out/x86-production-cli.log`.

The complete suite is installed at `out/install/X86ModeDebug`. Ordinary package
checks, installed project/recovery tests, all nine native desktop workflows,
installed engine/native-oracle checks and actual 32/64 application launch/module
checks passed in `out/x86-install-validation.log`. Validation executables were
copied without engine DLLs; their child PATH resolves the package's installed
runtimes. Actual application module paths were checked against installed `bin`.

Normal and compact raw32 native views are captured under the build and installed
`validation/artifacts/x86-mode-{normal,compact}.png` directories. Actual packaged
PE32 application views are in
`out/install/X86ModeDebug/validation/actual-application/installed-x86-32-{normal,compact}.png`.
These images were inspected for visible instructions, matching bytes, usable
listing space and the active mode label; native assertions separately verify
interaction and model state.

`out/x86-binary-audit.log` verifies all production engines are wx-free, private
checkpoint exports and test targets are absent, and both fresh headless trees
have no `_deps` acquisition directory. The stage-3 installation at
`out/install/ProjectAnalysisDebug` remains untouched as a compatibility baseline.

The fresh independent review found a P2 continuation-formation defect and a
missing x86-32 persistent-decision proof. Both are addressed: both recovery paths
share an architectural continuation rule, wrapped fallthrough targets start a
separate block, and the recovery engine fingerprint advances to v3 without
changing cache format v2 or user schema 1. Regressions pin NOP/Jcc/CALL EIP32
wrap, the low IP16 return address of a 16-bit near CALL, unchanged EIP32 on an
untaken 16-bit conditional transfer, and cache reconstruction. Additional raw32
command tests exercise persisted code/data/function/chunk/suppression decisions
and undo/redo before and after close/reopen. Targeted tests pass in
`out/x86-review-regression-green.log`.

The review used source inspection and focused scratch execution against installed
Debug DLLs; it did not independently repeat the complete delivery matrix. Final evidence after that fix:

| Check | Result | Evidence |
| --- | --- | --- |
| Debug and Release headless | 44/44 each | `out/x86-review-final-headless.log` |
| Full Debug desktop | 55/55 | `out/x86-final-capture-desktop.log` |
| Disconnected headless and production rebuild | 44/44; Release build passed | `out/x86-review-final-offline-production.log` |
| Production project CLI | passed | `out/x86-review-final-production-cli.log` |
| Complete installed workflows and actual 32/64 launch | passed | `out/x86-capture-recovery-final.log` |
| Engine/test-import separation | passed | `out/x86-review-final-binary-audit.log` |
| Original independent review reproducer against updated installed DLLs | corrected 2/3 instruction recovery and continuation edges | `out/x86-review/boundary-fixed-output.txt` |

Final capture inspection initially exposed blank images in a repeated run.
Capture helpers now explicitly show their own window without activating it,
synchronously redraw and use PrintWindow with opaque RGB output; mostly blank
images fail validation. All four replacement installed raw32/PE32 normal/compact
images were inspected and are readable. The repeated installed graph test also
now waits for current reference derivation instead of racing an accepted edit
against intentionally empty pending-reference rows. These are validation-only
changes. Final full desktop tests pass 55/55, and complete installed workflows
pass again in the logs above.

The scoped x86-32 subproject is accepted. This closes neither the remaining
stage-4 processor/format/type work nor the full IDA-class suite objective.
