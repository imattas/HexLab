# ARM processor implementation plan

> Execute with superpowers:executing-plans inline under standing authorization. No per-task agents, commits or index edits. One fresh immutable whole-stage review after all delivery evidence exists.

Spec: docs/superpowers/specs/2026-10-21-arm-processors-design.md
Goal: A64/A32/T32 processors integrated with the existing shared engine and real project workflows. Existing original implementations and suitable licensed upstream code are both permitted by the user's 2026-10-21 instruction. Record immutable source pins, local changes and installed notices for code actually incorporated; candidate research is not an integration claim.

## Preconditions and review focus

Work in existing G:/HexLab checkout: HEAD is unborn; never invent a base commit or create an empty worktree. Preserve original staged foundation documents. Maintain .superpowers/sdd/2026-10-21-arm-processors/progress.md. Accepted MachODebug and ElfDebug are immutable. New output stays under explicit ARM prefixes; dated cleanup script remains retired. Tests use literal source inputs, never launch them. Decoder/engine ABI changes require complete consumer rebuilds before execution.

Risks each owned by tests below: (1) x31 SP/zero confusion and flags/LR effects (Task1); (2) Thumb state bits, PC biases and32-bit truncation/IT state (Task3/4); (3) bit-packed relocation placeholders becoming false callees (Task2/5); (4) old caches, forged mode/source and stale workers (Task4/6); (5) self-confirming disassembly text or production oracle dependency (Task7).

## Task1: preserved engine20 and original A64 scalar decoder

Files: new out/arm-cache-v8-v20-capture producer/source/runtime/project/provenance (generated evidence); tests/fixtures/derived_v8_arm_v20.* and exact original input/producer; core/architecture.hpp; processors/instruction.hpp; processors/src/a64_{internal,decode,flow,data,format} files; processors/{decoder,format}.hpp/src/dispatch.cpp/CMakeLists; tests/a64_decoder_tests.cpp and tests/CMakeLists; analysis/functions.cpp engine identity.

Interfaces: existing decode_instruction(DecodeContext, span<byte>, Address)ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢DecodeResult; public decode_a64(span<byte>,Address) convenience; existing processor_capabilities and format_instruction. Append mode a32=4/thumb=5/a64=6, register banks and dedicated A64 opcodes. Preserve all old numeric values/variants/record shapes. No foreign production dependency.

- [x] Capture actual engine20/schema8 before edits in a new prefix, source/runtime/SDK/exe/input/project/payload/ref hashes. Producer copies adapted from current genuine19 producer only to label output20, executes matching copied20 DLLs once. Verify results and seal. Promote byte-identical evidence, never rerun against21.
- [x] RED tests: literal `14000002` B at0x1000ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢0x1008; `97ffffff` BLÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢0xffc plus x30 write/no stack; `54ffffe1` B.neÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢0xffc+NZCV read; `b4000040` CBZ x0ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢0x1008; register branches/return; NOP/BRK; MOVN/Z/K widths/halfword restrictions; ADD/SUB immediate x31 SP versus flags/ZR; ADR/ADRP negative/page alignment; LDR/STR widths/baseSP/valueZR. All proper prefixes truncated, misaligned address invalid, context/endian/segmented/stack mismatches unsupported, extension encodings not claimed. Branch overflow has no target. Every test checks typed effects and exact bytes, not text alone.
- [x] Implement focused files with decode-only pure arithmetic, checked signed displacement math, four-byte bounded reads; packed fields stay absent from byte EncodedField. Zero register omitted from state effects, actual flags/LR banks explicit. Add context-aware ARM formatter dispatch; old x86 formatting unchanged. Advance engine identity21 before supported decoder semantics are published.
- [x] GREEN literal tests plus generated register/immediate boundary matrix. Full headless Debug/Release and desktop after complete rebuild; retain RED/GREEN logs. Do not mark whole processor family verified.

## Task2: A64 image/flow/reference/cache integration

Files: loaders raw/recipe/PE/ELF/Mach-O image sources; analysis/instruction_flow.hpp, source_context and generic references/cache validators; tests/a64_{image,analysis,cache,relocation}_tests.cpp; CLI raw arguments/profile output; shared raw options/native open dialog.

Interfaces: explicit a64 raw recipe on64-bit domain; loader contexts select a64 only for compatible CPU/class/order. continuation_address understands a64. References retain original instruction words and no x86 register/stack assumptions. Per-type relocations consume decoded opcodes and source words, not invented byte operands.

- [x] RED raw/PE/ELF/Mach-O literal A64 entry/call/conditional/literal-memory images; incompatible class/order stays metadata-only. Direct and unresolved relocations cannot claim placeholder callees. Boundary/gap/excluded/encrypted instruction windows stop exactly.
- [x] Implement shared flow and typed register validation for appended banks; ensure derived/source/reference round-trip, canonical decode checks and valid-checksum semantic forgeries reject. Add source-bound A64 CALL26/JUMP26/ADRP-related relocations only with authoritative pairing; unsupported variants remain typed unresolved.
- [x] GREEN actual recovery/functions/blocks/references/Follow and source-missing embedded cache reopen; six MachO historical fixtures plus captured20 recompute readonly preserving user/history. Run full gates.

## Task3: original A32 and T32 decoding

Files: processors arm32/thumb focused decode/flow/data/format files; instruction typed ARM operand/control extensions; tests/arm32_decoder_tests.cpp, thumb_decoder_tests.cpp; cache instruction codec and explicit version advance when new fields enter wire.

Interfaces: decode_a32/decode_thumb convenience and shared dispatch. Explicit typed predicates, shifted registers, register lists, writeback, ARM PC behavior and interworking state metadata; no x86 flag/stack imitation. Thumb32 incomplete prefix is truncated. Initial supported scalar families include branches/calls/BX/BLX, data processing, load/store, stack/multiple registers, condition and IT semantics; coverage ledger names other instruction families still open.

- [x] RED literal matrix of conditional operations and flags/carry, ARM PC+8/Thumb PC+4+alignment,16/32-bit boundaries, LR/state-bit exchanges, IT ambiguity, forbidden registers/forms and reserved encodings.
- [x] Implement typed effects and packed-bit provenance; update canonical codec before cache can publish new shapes. Preserve actual22 A64 project/cache/relocation facts before the next incompatible semantic advance in a new prefix; genuine23 and24 also preserved before subsequent phase advances.
- [x] GREEN decoder/formatter independent fixtures and full gates: phaseC108 Debug/108 Release/122 desktop-alone; four compiler corpora27/15/43/75 per configuration, all8139 protected hashes unchanged. Initial subsets only; remaining wide/system/ISA coverage remains partial and Task4 source-bound adoption is still required.

## Task4: source-bound mixed-state contexts and durable mode operations

First dependency phase (inline, no separate reviewer): implement the image-context
contract in the spec with RED/GREEN coverage for modes, data/gaps/conflicts,
boundary windows, roots, source evidence, canonical identity and invalid profiles.
Use the sealed actual25 capture before advancing engine26; retain schema11/ref9.
Extend actual22/23/24 migration coverage with actual25. Rebuild all ABI consumers,
then run headless Debug/Release and desktop alone. Keep the automatic ARM guard
until source-bound IT/flow work is ready. This phase does not close Task4.

- [x] Image-context dependency phase: RED/GREEN71 range/context/root/provenance
  checks;64 checks for actual22/23/24/25 migration. Rebuilt all consumers;
  Debug109/109117.32s, Release109/10989.75s, desktop-alone123/123139.94s.
  Twelve fresh compiler reports480 projections/108 identities and8846 preserved
  file records all match. Engine26/schema11/ref9/DBref10; automatic ARM guard
  remains. Logs/audits: out/arm-task4-context-*.

Files: image code-context ranges/lookup/mapping identity; ELF mapping-symbol state and Thumb symbol values; platform mode facts; raw ARM profile parser/recipe; database user operation/migration; workspace operations/analysis and analysis flow/source/cache code; tests/arm_context/project/workers/cache tests.

Next dependency phase: preserve actual26; RED literal ARM recipe-v3 recognition,
then add bounded raw ARM profile parsing/validation/format/read, raw mapping,
canonical durable recipe, worker opening path and both CLI parsers. Prove real
project rename/patch/undo/redo/SaveAs and readonly source-missing reopen with the
external profile removed. Add actual26 migration fixture to the prior producer
matrix. Full Debug/Release and desktop-alone gates after all consumers rebuild.
Engine27/schema11/ref9/DBref10; keep automatic-flow guard. Durable mode overrides
and source-bound IT/flow still remain Task4 work after this phase.

- [x] Durable raw-profile dependency phase:207 profile/project checks,80 actual
  producer22/23/24/25/26 migration checks and9 CLI commands per configuration.
  All consumers rebuilt; full Debug111/111147.48s, Release111/11196.34s,
  desktop-alone125/125125.49s. Thirteen captures+two accepted installations
  retain9560 file hashes. Twelve compiler reports480 projections/108 identities
  and three raw CLI reports27 commands/27 runtime identities verified. New
  engine26 capture714 sealed records; five exact promotions. Current27/11/9/10.
  Logs/audits: out/arm-task4-raw-*. Full Task4 remains open.

- [x] ELF32/ARM mode declarations: executable-section `$a`, suffixed `$t`, and
  `$d` symbols create initialized bounded source-backed ranges. Odd STT_FUNC
  values retain the raw Thumb bit while exposing an even physical address and
  function-root IT claim. Contradictory function/mapping and same-address
  mapping claims become explicit conflicts. Literal ELF symbol fixture passes
  focused Debug `elf_symbols`; full Task4 remains open.

Interfaces: immutable bounded disjoint context intervals in ImageLayout, source-bound to raw/project declarations. Explicit state-bearing code targets separate physical address and execution state. Mode override transactional and undoable. Conflicting contexts remain conflicts. New metadata affects mapping/cache identity; all consumers validate it.

- [ ] RED real mixed ARM/Thumb/data section, equal offsets across domains, odd Thumb entry, exact transition agreement/conflict, IT propagation boundaries, bounded range paging/cancellation, patch invalidation, readonly old-cache migration and forged context identity.
- [ ] Implement authoritative mode intervals and state-aware traversal/continuations; no automatic odd-address decode or heuristic instruction-state switching.
- [ ] GREEN CLI/project analysis plus held worker late completion, cancellation and source-missing durable reopen. Full gates.

## Task5: ARM family relocations and source-bound flow

Files: loaders ELF/Mach-O/PE architecture relocation parsing as needed; analysis arm_relocations resolver/provenance codec, generic flow/source context; tests/arm_relocation/{literal,compiler,provenance}_tests.

Interfaces: pure borrowing resolver returns typed symbolic/static/runtime/unsupported outcomes with original table/word/operand-bit evidence. ARM/Thumb branch relocation uses state plus exact source instruction form. Paired pages/split immediates require matching source namespace and recorded order.

- [ ] RED real object CALL/JUMP/Thumb wide call/interworking/movwide/page relocations, undefined imports and duplicate indexes/domains; forged proof/checksum/target/packed bits must fail. Bounds, ambiguity, unsupported/PAC/runtime stay explicit.
- [ ] Implement only proven equations with no host-library linking or execution. Preserve prior semantic engine before any advance.
- [ ] GREEN literal/compiler differential facts and actual decoded Follow/owned references versus raw declarations. Full gates.

## Task6: complete CLI/wx project workflows

Files: CLI shared raw choices/profile/state output; desktop open and processor context presentation/commands; workspace immutable indexes; tests/arm_cli_tests.cmake, desktop_arm_tests.cpp, arm_project_tests.cpp.

- [ ] RED A64/A32/T32 and mixed mode open/analyze/jump/follow/incoming/outgoing/name/comment/patch/undo/redo/export/SaveAs/source-missing reopen through actual CLI and real wx frame. Mode command affects correct document only. Held stale job cannot publish to another tab or context revision.
- [ ] Implement native workers/indexed presentation; GUI does no decoding or scans. Keep unavailable transitions visible rather than inventing targets.
- [ ] GREEN exact export bytes/new UUID/preserved history/selected mode and readable normal/compact nonblank owned-window captures. Full gates.

## Task7: independent oracle, production/delivery and one final review

Files: tests/arm_oracle.py, arm_oracle_probe.cpp, fixtures/arm_oracle original assembly/C/tool hashes; tests/sdk/arm consumer and arm_install_tests.cmake; docs/arm-coverage.csv and arm-validation.md, capabilities/building; new out/install/ArmDebug only.

- [ ] Compile real A64/A32/T32 objects and linked fixtures with pinned clang/lld; compare typed opcode/register/flow/word/relocation/context facts against official ISA and observed LLVM. Alias differences labeled; semantic mutation negatives and missing tool hard failures. No ARM input execution or CPU-equivalence claim without actual execution proof.
- [ ] Full Debug/Release/desktop-alone/disconnected/productionBTOFF suites and engine-DLL/dependency/test-export boundaries; installed public SDK and actual engine/CLI/native/module-path/source-missing checks. Any newly incorporated dependency needs a pinned source inventory, license notices and explicit packaging coverage. All historical archives/accepted installs retain every recorded hash.
- [ ] New ArmDebug installation contains current SDK/source/licenses/resources, engine and wx DLLs and both tools. Copy logs/oracle/review evidence and hash every installed file; actual owned-window images visually inspected.
- [ ] One fresh immutable whole-stage reviewer, parent regrades every finding and declined judgment; material findings one RED/GREEN fix pass+all affected/full gates, record rulings and close only this ARM plan. Full objective remains active for types/ABI/debug/decompiler/plugins/platforms and remaining ISA matrix.

Self-review: every spec contract maps to Task1ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“7. Fixed-width A64 is a task, not the family completion criterion. Mixed-state/data/relocation/persistence contracts retain dedicated tests. Standing approval and inline method preserve continuous execution.
### Task3 phaseA execution detail

- [x] Capture genuine engine22 A64 object/project/cache/reference facts with matched SDK/runtime/source before mutation: NEW out/arm-cache-v8-v22-capture;670 sealed records, original984-byte ELF,5452-byte HXDC and1669-byte reference payload. Original symbols owner2:0/callee4:0, seven instructions/six owned relocations.
- [x] Add pure A32 control-transfer literal tests before product code: PC+8 B/BL, link PC+4, 14 ordinary predicates, BLX immediate H bit/Thumb state, register BX/BLX and return, NOP/BKPT/SVC, truncation/alignment/32-bit overflow/context guards. Assert predicate/flags/LR/state facts and source bytes.
- [x] Append ArmInstructionInfo and A32 opcodes; implement arm32_decode and arm32_format in processors. Dispatch only the declared A32 control subset. Keep loading/state-aware automatic analysis disabled until Task4.
- [x] Advance derived9 and engine23; serialize/compare bounded ARM metadata; keep references7/cache8 until the reference expression shape changes in phaseB. Update old-version tests using genuine captured versions, not altered fixture bytes. Add genuine22 A64 cache compatibility test with embedded readonly user/history preservation.
- [x] Full Debug/Release/desktop-alone gates, compiler A32 branch projections and immutable archive audits. Observed102 Debug42.93s/102 Release29.41s/116 desktop111.89s; six oracle reports (27 A64 +15 A32 each configuration),6763 preserved records, zero mismatches. Record this phase and continue phasesB/C of Task3; no whole-stage reviewer before Task7.

### Task3 phaseB execution detail

- [x] Capture genuine engine23/schema9/ref7 A64 object/project/cache facts with matched freshly installed SDK/runtime/source before new operand semantics: NEW out/arm-cache-v9-v23-capture;682 sealed records, five byte-exact promotions.
- [x] RED then implement all sixteen basic A32 ALU operations, rotated immediates, typed immediate/register-controlled barrel shifts and RRX carry input; guarded partial NZCV writes and explicit unknown conditional C updates. Preserve PC data sources and Armv7 PC-write exchange; exception/status/multiply/movwide forms remain unsupported.
- [x] RED then implement typed single-transfer memory (offset/pre/post/add/subtract/writeback, byte/half/word, signed loads, checked PC+8 literals) and register masks with IA/IB/DA/DB modes, explicit PC loads and stack-return effects. Reject disabled unprivileged/overlap/user-bank/empty-list/doubleword forms.
- [x] RED then implement bounded shared ARM operand codecs, canonical instruction validation and ARM memory reference expression. Advance actual derived9 to10, engine23 to24, standalone references7 to8 and database reference cache8 to9. Keep standalone7 readable with its original key; reject checksum-valid7 carrying the new tag. Genuine22/23 readonly migration preserves old bytes and user history.
- [x] Compare43 original compiler scalar words/text plus existing15 A32 controls/27 A64; record nine exact observed A32 spelling/alias equivalences, and enforce branch-target/register-shift mutation negatives. No input execution or linked-target claim for unlinked relocation words.
- [x] Final full Debug106/106 (71.64s), Release106/106 (66.97s), desktop-alone120/120 (105.91s). All7445 historical/accepted records match; nine fresh oracle reports/255 projections/81 identities match. Observed documentation recorded. Continue Task3C Thumb/IT; full Task3 and Tasks4-7 remain open.

### Task3 phaseC execution detail

- [x] Preserve genuine engine24/schema10/ref8 with matched installed SDK/runtime/source before Thumb semantics: NEW out/arm-cache-v10-v24-capture694 sealed records, actual A64 object/project/cache/Follow/annotation and five exact promotions.
- [x] RED then implement Thumb narrow/wide framing, explicit unknown/known-no-IT/active IT, predicate and implicit-S handling, BKPT exception, forbidden IT/control combinations and physical link/target mode facts. Native A32 semantic helpers retain original Thumb bytes and3/7/8-bit immediate provenance.
- [x] RED then add distinct ThumbRelativeOperand and bounded reference expression, preserving existing A32 range/alignment negatives. Advance25/derived11/ref9/cache10; retain standalone7/8 readers under original identities. Canonical decoder consumes incoming IT state and checks full record; source-chain proof/adoption remains Task4.
- [x] Literal1468 Thumb assertions,48 actual22/23/24 migration and68 operand/reference codec assertions pass; original A32/A64 suites remain green. Independent Thumb75 corpus has actual narrow/wide branches and explicit IT chain/length validation, no input execution.
- [x] Full gates108Debug83.72s/108Release75.03s/122desktop121.29s alone;12 oracle reports480 projections108 identities match;8139 protected records match. Observed source/docs/capabilities updated. No whole-stage review before Task7.

Task3 closes only the initial decoder subset. Remaining Thumb32 data/memory/system and other ISA families are partial; full objective remains active. Task4 must validate source mode/IT roots/prefix chains, distinct state/fact identity and computed PC-transfer expressions before automatic analysis. Unsupported packed relocations must block following placeholder targets until source provenance/equations are proven. Capture genuine25 matched runtime/SDK/source/cache in a NEW prefix before the next semantic advance.
