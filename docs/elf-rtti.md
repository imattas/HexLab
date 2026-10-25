# ELF Itanium C++ RTTI metadata

The ELF64 loader exposes structural RTTI in `ElfMetadata::rtti_classes` and
`ElfMetadata::vtable_headers`. Addresses are link-time image addresses. The
records preserve the `_ZTI`/`_ZTV` symbol index and mapped object addresses;
class names are the mangled strings stored in the ABI `type_info` objects.

The bounded parser recognizes `abi::__class_type_info`,
`abi::__si_class_type_info`, and `abi::__vmi_class_type_info` descriptors by
resolving their descriptor vtable pointers to the corresponding ABI `_ZTV`
symbols. It reads the `type_info` name pointer, the single base pointer, or the
VMI flags/count/base array. Base records retain the encoded offset/flags and
separate decoded offset, virtual-base, and public-base fields. Primary vtable
headers retain the two-word offset-to-top/type_info prefix and mark the address
point immediately after that prefix.

For a primary vtable header with offset-to-top zero and a type_info pointer to
a recognized RTTI record, the loader also records bounded function slots from
its address point. Each slot retains its index and storage address plus one of
these states: a resolved executable image target, null pointer, unresolved
pointer, ambiguous pointer, or non-executable target. The target field is set
only for a unique pointer into initialized executable image bytes. Raw pointers
and unique validated relocations are considered; unresolved relocations do not
turn zero-filled slots into nulls. Slot scans stop before a later recognized
two-word secondary-table header and never interpret that table's slots.
`slots_scanned` is set only when this primary-table path is validated;
`slots_complete` is false when slots were not scanned or when a scan stops
before the `_ZTV` symbol extent, including at that secondary-table boundary,
or reaches a configured cap.
Each vtable is limited to 65,536 slots and all vtables together to 1,000,000
slots; cancellation and the loader metadata budget apply.

Every metadata read is required to land in initialized image bytes. Pointers
are accepted only when the raw pointer or a unique, validated in-image
relocation establishes one target. Null, missing, ambiguous, unmapped, or
zero-filled targets are left unresolved; an affected relationship is not
published as if it were established. Counts are capped at 100,000 RTTI symbols
and 4,096 bases per class; type names are capped at 1,024 bytes. Cancellation
and the loader metadata allocation budget apply.

Coverage is intentionally limited to ELF64 executable/shared-object images
with the Itanium ABI class descriptor families above. ELF32, relocatable ET_REL
objects, ELF core files, construction-vtable groups, secondary vtable slots,
pointer/function/member RTTI, fundamental/array/enum RTTI, mangled-name
demangling, and ABI variants with different layouts are not interpreted.
Descriptor families whose runtime ABI vtable symbols are absent or ambiguous
remain opaque. Slot addresses are metadata only: this parser does not bind
virtual call sites to slots, execute code, or establish complete C++ subtype
semantics.

The analysis reference index adds a cross-reference from a validated primary
vtable slot to its target only when the loader resolved that slot uniquely to
executable bytes. The reference retains the vtable symbol start, address point,
type_info address, slot address/index, and optional mangled type name. Null,
unresolved, ambiguous, non-executable, and secondary-table slots do not create
code-target references. If RTTI scanning is incomplete, the reference index is
also marked incomplete.

The layout follows the Itanium C++ ABI's RTTI and virtual table sections:
[RTTI layout](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#rtti),
[virtual table components](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable-components).
