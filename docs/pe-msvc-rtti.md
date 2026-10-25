# Bounded MSVC x64 PE RTTI discovery

The PE loader discovers structural Microsoft C++ RTTI candidates in AMD64
PE32+ images and publishes `PeMetadata::msvc_rtti`. This is source-backed
metadata inspection. It does not recover C++ object sizes, execute RTTI helpers,
perform `dynamic_cast`, create function roots or identify runtime virtual-call
targets.

Discovery runs before base-relocation overlays. All descriptor links, address
points and in-image targets are stored as RVAs. Original encoded pointer VAs
remain tied to the preferred image base. Rebased images retain the same RVA
identities and original file source spans.

The supported layout is the image-relative, signature-1 AMD64 Microsoft ABI:

- A 24-byte `CompleteObjectLocator` contains signature, object offset,
  constructor displacement, TypeDescriptor RVA, ClassHierarchyDescriptor RVA
  and a self RVA. A four-byte-aligned candidate must have signature 1 and a
  self RVA equal to its exact record location.
- A TypeDescriptor retains its two eight-byte header values and a bounded,
  NUL-terminated printable ASCII decorated class/struct name beginning `.?AV`
  or `.?AU` and ending `@@`. Its `type_info` vftable pointer may remain null or
  external; it is not used to invent an import binding.
- A ClassHierarchyDescriptor requires signature zero and the known multiple,
  virtual and ambiguous inheritance attribute bits. Its image-relative base
  array is decoded in declared order, including the self descriptor.
- BaseClassDescriptors retain type RVA, contained-base count, raw attribute
  bits and signed PMD member/vbptr/vbtable displacements. The optional hierarchy
  link is retained when `BCD_HASPCHD` is present. Its target header must be
  initialized readable data; this link is not recursively expanded.
- A vftable candidate starts after an eight-byte preferred-base VA pointing
  to an accepted locator. Subsequent eight-byte words are classified as
  initialized executable targets, null, initialized non-executable data,
  unmapped/uninitialized in-image pointers or outside-image pointers.

COL and vftable-prefix scanning covers initialized, readable, non-writable,
non-executable sections, excluding the PE header mapping. Referenced
descriptors may occupy writable readable data, as ordinary TypeDescriptors
often do. Every consumed descriptor extent must fit the image and initialized
readable non-executable mappings; records may span adjacent mappings. Candidate
anchors and pointer words must fit wholly within one scanned section.

Base counts and nested contained-base intervals are checked before publishing
the hierarchy. `parent_index` records only the consistent preorder relationship
encoded by those intervals. Repeated types, virtual inheritance and ABI
ambiguity flags remain visible; no unique object adjustment is inferred.
Virtual-base PMDs are never evaluated against guessed vbtable contents.

Every locator, hierarchy, array entry, base descriptor, TypeDescriptor header,
name, vftable prefix and slot observation retains file spans. A structural
candidate with malformed or unsupported referenced records remains a locator
row with its raw fields, explicit state and diagnostic. Independently decoded
types/hierarchies may therefore remain present even when one referencing
locator is rejected. Only locators whose self-type and hierarchy agree may
anchor vftable candidates.

Vftable records remain explicitly `unresolved`: a contiguous executable-pointer
run does not establish its complete extent. Walking stops at another accepted
locator prefix, the first non-executable word, the scanned-section boundary or
a slot limit. The first null/non-executable word is retained as a
`boundary_probe`, without asserting table membership. Stop reasons distinguish
actual initialized-section end, scan-budget truncation and slot truncation.
An executable target can separately report an exact match to a validated PE
runtime-function begin RVA. A function-entry match is evidence only; leaf
functions and thunks need not have their own exception-directory rows, and no
signature or runtime dispatch conclusion follows from a match.

The scanner enforces these independent bounds:

| Resource | Limit |
| --- | ---: |
| Read-only section bytes scanned | 32 MiB |
| Locator candidates / vftable candidates | 4,096 each |
| Types | 16,384 |
| Base descriptors per hierarchy | 4,096 |
| Aggregate attempted base descriptors | 65,536 |
| Decorated name including terminator | 4,096 bytes |
| Retained decorated-name bytes | 1 MiB |
| Charged descriptor/name inspection work | 8 MiB |
| Slot observations per table / aggregate | 256 / 65,536 |

The descriptor-work budget also charges unsuccessful candidates and reserved
name inspection extents, so it can bind before the individual record limits.
Runtime-function entry lookup uses a sorted bounded index rather than scanning
the entire exception table for each slot. Cancellation is checked throughout
section, record and slot loops. Budget truncation preserves accepted rows and
sets `discovery_complete=false`; the loader emits a warning and marks metadata
incomplete. Allocation/read failures follow the existing optional-metadata
warning path. A rejected candidate alone does not invalidate the PE image.

Unsupported discovery forms include PE32/x86 absolute-pointer RTTI, ARM/ARM64
and other machines, signature-zero locators, RTTI stripped by `/GR-`, writable
or executable COL/vftable storage, relative function-pointer vftables, unresolved
runtime/import pointer binding, unknown hierarchy/base attribute extensions,
and non-class/struct TypeDescriptor name forms. No PDB/type-library import,
automatic class layout recovery, vbtable evaluation or decompiler dispatch
integration is included. This pass does not claim exhaustive RTTI discovery.

Layout references are the Microsoft ABI structures emitted by
[Clang's Microsoft C++ ABI implementation](https://github.com/llvm/llvm-project/blob/main/clang/lib/CodeGen/MicrosoftCXXABI.cpp),
including its TypeDescriptor, BaseClassDescriptor, ClassHierarchyDescriptor and
CompleteObjectLocator layouts. The implementation is independently written.

This addition received source review only. No builds or tests were run.
Follow up with serial `hexlab_image`, `hexlab_loaders`, CLI and desktop builds;
the public PE metadata shape and source-header include graph changed.
