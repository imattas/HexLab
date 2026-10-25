# 32-bit Mach-O Objective-C metadata

The mapped-image scanner supports the little-endian 32-bit ObjC2 on-disk ABI
alongside the existing 64-bit path. This is the class-list runtime used by
32-bit non-fragile Objective-C images, not the ObjC1 `__OBJC` runtime.
`MachOObjCScan::pointer_bytes` records the selected four- or eight-byte width.
A selected slice whose pointer width or byte order disagrees with the mapped
image is rejected; arm64_32 is explicitly unsupported.

The 32-bit class-list slots are four bytes. `class_t` is five 32-bit pointer
fields (20 bytes); the superclass and data slots are at offsets 4 and 16.
The low two fast-data flags are cleared before following the data pointer.
The 40-byte `class_ro_t` prefix contains flags, instance start and instance
size at offsets 0/4/8, and name/method/protocol/ivar/property pointers at
16/20/24/28/36. Direct metaclass prefixes and their class-method lists use the
same width. An inconsistent instance start/size pair makes the record partial.
Realized, future or bundle runtime-data flags stop class-ro interpretation;
`class_rw_t` and runtime heap objects are not guessed from their storage.

Legacy absolute `method_list_t` records have an eight-byte
`entsizeAndFlags,count` header and at least twelve bytes per entry: selector,
type-encoding and IMP pointers. The low two fixup markers are separated from
entry size. Entry strides must meet the record minimum, pointer alignment and
4096-byte ceiling; count, initialized segment extent and aggregate read budgets
are checked before payload decoding. Unknown encoding flags, direct-selector
flags without relative encoding, and 32-bit small/relative lists remain partial
with explicit statuses. Rejected lists retain available count/stride evidence
but are never decoded as absolute entries. Existing supported 64-bit relative
lists retain their separate format.

Pointer reads require width-matched address domains and aligned complete slots.
Relocation/dyld-owned fields preserve the existing resolved, runtime-bound,
authenticated, ambiguous and unsupported statuses; unresolved fixup storage is
never reinterpreted as a raw pointer. Raw pointers require initialized readable
source bytes and a mapped target. Resolved targets outside the pointer domain
are rejected. All address extents respect the mapped domain's width.

An IMP must refer to enough file-backed executable bytes for the entry mode,
remain outside encrypted/excluded code and agree with an authoritative ARM
profile when one exists. ARM32 bit zero is retained in
`encoded_implementation` and interpreted as Thumb state, while a validated
`implementation` uses the canonical address. `implementation_pointer_status`
retains pointer provenance even when executable-range validation fails;
`implementation_mode` retains the ARM state indicated by the source pointer.
A32 entries require four-byte alignment and four bytes of code; Thumb entries
require two bytes. Other IMPs require a file-backed executable byte.

The shared stable 32-bit protocol/category prefixes remain bounded: eight
pointer fields for protocol definitions, six for categories, pointer-sized
protocol counts/references, 20-byte ivars and eight-byte properties. Ivar
default alignment follows the four-byte word size. Type encodings receive the
selected pointer width, so `long`, object and block pointers use 32-bit sizes.
Links and deduplication use the complete address-space ID plus offset.

ObjC1 module/class/category/protocol records in `__OBJC`, big-endian images,
arm64_32, small/relative 32-bit method lists, tagged relative-list-list unions,
runtime caches and realized/future runtime objects are intentionally unsupported.
Optional category class-property tails, protocol extended method-type arrays,
demangled-name/class-property tails, Swift initializer tails and private runtime
extensions are not inferred. Unsupported source evidence marks the scan partial
while retaining already decoded rows and field statuses. Native runtime code
is never executed. No builds or tests were run for this hardening slice.

Layout references: [Apple objc4 runtime definitions](https://github.com/apple-oss-distributions/objc4/blob/main/runtime/objc-runtime-new.h).
