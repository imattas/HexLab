# x86-16 and explicit segmented raw analysis

## Intent and authorization

Build the next working part of the original C++20/wxWidgets IDA-class monorepo:
16-bit scalar decoding with real/protected segment coordinates, persistent raw
profiles, shared analysis and real CLI/native workflows. User standing approval
explicitly removes further approval checkpoints. Preserve architectural design,
planning, tests and one fresh final review, and continue inline without asking.

This is stage4b, after accepted x86-32 stage4a. It does not complete the full
objective. DOS MZ/NE/LE loading, remaining processor variants, ELF/Mach-O,
ARM/AArch64, types/ABI, debug imports, signatures and the later IR/decompiler,
debugger, SDK, platform and breadth stages remain required. Raw profiles make
segmented input usable now; they do not stand in for those file-format loaders.

## Existing contracts and design choice

Address is already an address-space ID plus an unsigned offset; FileOffset is
distinct. Keep that identity. Give each declared logical segment its own stable
address-space ID and store its logical offset in Address.offset. Do not flatten
CS:IP into a numeric file position or silently merge selector aliases. An
explicit profile translates logical locations to linear/real physical locations
and canonical file spans. Multiple logical locations may share one input byte;
reverse file navigation stays ambiguous instead of choosing an arbitrary alias.

Compared alternatives: flat16 only loses segmentation and aliases; replacing
Location everywhere with a new pointer union needlessly breaks every existing
consumer. Extending the existing space-aware image and making segment translation
explicit preserves current typed identities and exposes the missing semantics.

The first supported execution profiles are 386-style real address mode and
declared 16/32-bit protected code/data descriptors. Do not claim exact 8086/286
exception behavior, virtual8086, unreal-mode hidden-state inference, paging,
privilege-changing gates/tasks or an emulator. Unsupported transitions remain
typed unresolved/partial facts. These variants remain open in the full matrix.

## Core segment coordinates

Add core/x86_segments.hpp and focused original implementation sources:

- X86LogicalAddress { uint16 selector; uint32 offset }, X86LinearAddress and
  X86PhysicalAddress are distinct trivial values. Neither converts to FileOffset.
- A20Policy is explicitly enabled/disabled. real-mode linear translation validates
  the complete access against the 386 64KiB logical domain, then forms the linear
  address. A separate physical translation applies A20 policy. Return at most two
  typed physical spans when the physical window splits; retain exact byte count.
- X86SegmentDescriptor records base, effective byte limit, present/code/read/write,
  expand-down, D/B, conforming and DPL attributes. Parse exactly eight descriptor
  bytes with checked little-endian reads. System/gate and long-code descriptors
  are unsupported here; never reinterpret them as ordinary data/code.
- Protected translation checks null-selector use, presence, local access type and
  the entire logical span. Expand-down bounds use limit+1 through the B-dependent
  ceiling. Produce one or two 32-bit linear spans if base addition wraps. The
  result is address translation, not a CPL/RPL, gate or paging authorization.
- Empty accesses still require valid coordinates; overflow and invalid enum/type
  combinations fail. Valid results require no storage reads or allocation.

Initial literal canaries: 1234:5678 -> 179B8; 1000:0010 and 1001:0000 remain
different logical pointers with equal translated position; FFFF:FFFF is 10FFEF
with A20 enabled and 0FFEF with it disabled. FFFF:000F plus two bytes splits at
the A20 boundary. A logical word at offset FFFF violates a 386 segment limit;
do not confuse that fault with physical A20 wrapping. Descriptor limit 0 with
G=1 includes the first 4096 bytes; expand-down excludes the limit itself.

## Image domains and lookup

Extend ImageLayout with additional domains and immutable segment-profile metadata
while retaining the existing primary space/architecture/mode fields and all flat
aggregate initializers. Each domain has an AddressSpace and DecodeContext. Add
Image::space(id), context_at(Address), and explicit logical-selector/linear/file
translation queries. Unknown space/context fails; context_at never inherits the
primary mode for another space. Validate duplicate IDs, descriptor keys, backing
extents and overlap per logical space. Sort/index by (space,offset), not offset.

Normal PE/raw32/raw64 remain one-domain images with identical recipe bytes and
behavior. Appended value fields require full DLL consumer rebuilds. Canonical
input remains the stored original plus user patches; translating a segment must
not rewrite raw instruction bytes or leak loader assumptions into export.

## Original 16-bit decoder and typed transfers

Extend the shared original parser, not a duplicated or foreign decoder.
Default operand/address sizes are 16; 66/67 select 32. Code default size, near
target width, stack value width and stack address width are separate rules.
DecodeContext gains an explicit stack-address attribute: zero means the existing
profile's default; a protected profile supplies SS.B when it differs. Preserve
all current 32/64 aggregate defaults and enum numeric values.

Cover the established scalar families in 16-bit mode, including stack immediate
lengths, register widths, signed immediates, 16-bit address matrix/default DS/SS,
address override, near rel16/rel32 and returns. Add typed far pointer operands and
far CALL/JMP/RETF forms; distinguish value slots from total pushed pointer size.
Indirect far memory retains its expression and width and stays unresolved unless
proved. Segment MOV/POP/LDS/LSS, gates and uncovered forms remain explicit stops
until separately implemented; never carry invented register-state knowledge.

Use logical CS offsets for control flow, with encoding target widths and declared
code limits. EIP behavior must not be inferred merely from address-space display
width. Pin ordinary continuation, taken/untaken conditional paths and pushed
return IP against primary documentation and the independent execution fixture
before enabling recovery; include high offsets in D=0 protected segments.

## Raw profiles and user-facing behavior

RawOptions gains an optional bounded segmented profile. It declares environment,
A20 policy, contiguous input load position, code/data domain descriptors, logical
entry and static stack attribute. Derive initialized file intersections through
the checked translators, including aliases and physical splits. Missing selectors
are not invented. Profile bindings are explicit analysis assumptions, not inferred
runtime segment-register state. Data references whose segment value is not proved
remain unresolved, even when a DS/SS default register is known from the encoding.

Version segmented recipes independently; preserve existing raw32/raw64 v1 bytes.
Embed the full profile in the project so source-missing reopen works. Keep user
schema version1 if no authoritative schema change is required; derived cache v3
binds every record to its domain/context and profile digest. Capture genuine v2
payloads from the unchanged stage4a installation and prove readonly recomputation
without changing user history. Context-dependent decode fields are canonical.

Expose raw16 profile selection in both CLI parsers and the native mapping dialog,
with segment:offset entry/navigation and visible active domain/mode. Keep the
simple x64 default. A declared profile/file is preferable to an enormous argument
list: use one checked versioned UTF-8 profile format with precise diagnostics and
size/count limits, shared by CLI and wx. No decode, SQL or profile-file parsing
on GUI event handlers; actors/workers do that work.

Audit listing/function/search/reference sorting and lookup for repeated offsets
in different domains. Code/data/chunk edits, annotations, bookmarks, undo/redo,
SaveAs, patch export, cache/graph invalidation and mixed16/32/64 tabs retain typed
space identity. Local file search may have several logical aliases; do not guess
one. Direct real/same-level protected far transfers resolve only through declared
code descriptors; missing/unsupported/privilege-changing cases remain explicit.

## Independent execution and delivery

Windows x64 cannot supply the prior Win32 oracle's default16 code segment just by
adding prefixes. Provision pinned test-only QEMU and Bochs emulators, firmware and
NASM through their official distribution chains, recording exact versions, hashes
and notices. Extract under out/tools without global installation. Execute only
authored bounded real/protected16 probes with no network, user configuration or
arbitrary input execution path, explicit deadlines and deterministic records.
QEMU TCG supplies the14 safe size/alias/A20 records. Its observed translated-page
EIP truncation and omitted per-access limit checks make it unsuitable for these
boundary cases; Bochs supplies all24 records, including high EIP and real/data/code
limit faults. Bochs reaches an explicit DONE+CLI/HLT state before its own host
process is stopped, avoiding the vendor Windows binary's intermittent ACPI
teardown crash. Missing records or an earlier crash fails. Production does not
depend on these test tools. See the fixture README and tools.json for exact pins,
provenance, disconnected provisioning and runtime evidence.
Missing execution evidence is an unmet gate, never a passing skip. Native32/x64
oracles continue to run. Linux/macOS remain unverified until actual platform work.

Acceptance requires literal decoder/translation matrices, aliases/A20/limit tests,
multi-domain immutable reads, canonical caches and adversarial profiles, persistent
command/history/reopen/export workflows, independently executed16 probes, real
mixed-mode wx navigation and nonblank normal/compact captures. Run full Debug
desktop, Debug/Release headless, fresh disconnected/production builds, installed
workflows in a new SegmentedDebug prefix and one fresh independent final review.
Keep the stage3 and stage4a installed baselines untouched. Preserve the unborn
working branch; do not invent Git identity, commits, merges or cleanup menus.

## Primary references

- Intel SDM Vol3A, sections3.4/3.4.5/5.4 and Figure3-5:
  https://cdrdv2-public.intel.com/819714/253668-sdm-vol-3a.pdf
- Intel SDM Vol3B, chapters23/24 and section25.33 (CPU-generation differences):
  https://cdrdv2-public.intel.com/874250/253669-090-sdm-vol-3b.pdf
- Intel instruction operations for near/far CALL/JMP/RET:
  https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf
- QEMU official distribution/tool documentation:
  https://qemu-project.gitlab.io/qemu-web/download/
  https://www.qemu.org/docs/master/system/target-i386.html
- Bochs official release and CPU/device sources:
  https://github.com/bochs-emu/Bochs/releases/tag/REL_3_1_FINAL

These references guide behavior; no third-party decoder implementation is copied.
