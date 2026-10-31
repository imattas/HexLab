# UEFI FMP capsule metadata inventory

## Offline scatter/gather capture

One bounded `EFI_CAPSULE_BLOCK_DESCRIPTOR` form is supported explicitly:

```text
hexlab_cli firmware inspect memory.bin --capsule-sg-base 0x100000 --capsule-sg-head 0x101000 --format uefi-capsule
```

The positional file is the primary physical-memory capture. Its physical base
and the physical address of the first descriptor must both be supplied;
addresses are never guessed to be file offsets or dereferenced in live memory.
Both options accept the CLI's usual checked numeric-address syntax and must
occur exactly once as a pair. Additional sparse captures use repeated
`--capsule-sg-region BASE=FILE` options, for example:

```text
hexlab_cli firmware inspect primary.bin --capsule-sg-base 0x100000 --capsule-sg-head 0x101000 --capsule-sg-region 0x200000=payload.bin --format uefi-capsule
```

Each base must be unique, including the primary base. At most 256 total
regions and 512 MiB of cumulative capture bytes are accepted. Every descriptor
and data range must fit wholly inside one supplied region; overlapping physical
ranges are rejected by the parser. Text output lists each region's base, path,
and byte size. `--json` emits a bounded `hexlab.uefi-capsule-sg.v1` inventory
with region provenance and capsule stream offsets. These options are valid only
for `--format uefi-capsule`; JSON mode requires at least one additional region.
The original single-capture command retains its existing output.

`parse_uefi_fmp_scatter_gather_list(capture, physical_base, descriptor_head,
options, stop)` reads little-endian 64-bit Length/physical-address descriptor pairs.
The multi-region CLI form uses `parse_uefi_fmp_scatter_gather_regions` with the
same bounded parser options; returned descriptor records retain region indexes
and offsets for descriptor and payload provenance.
Nonzero Length contributes that data range to the logical capsule stream.
Zero Length with a nonzero target follows a continuation list; zero Length and
zero target terminates the chain. The selected offline profile requires a
nonzero, 8-byte-aligned head and 8-byte-aligned continuation addresses.
Sequential descriptors occupy 16 bytes and must be wholly captured. Descriptor
cycles, physical-range/arithmetic overflow, uncaptured descriptors/data, missing
termination, and empty chains fail. Data ranges may repeat; their logical
occurrences are retained separately in traversal order.

The capture is capped at 512 MiB and also obeys the nested capsule options'
input limit. `UefiCapsuleScatterGatherOptions` permits 1–4,096 descriptors,
including continuation/terminator records, and 1 byte–128 MiB of gathered data;
defaults are 4,096 and 128 MiB. The parser validates the entire bounded chain
before allocating one payload buffer, then copies in cancellation-checked
chunks of at most 1 MiB. It applies the existing FMP parser and embedded/nested
inventory budgets to the gathered bytes. Up to 256 persistent FMP capsules may
fill the logical stream, each delimited by its checked `ImageSize`, with no
inter-capsule padding or trailing data. A capsule after the first must begin
at a data descriptor following a continuation record at the same logical
offset, matching UEFI's conversion of a capsule's terminator into a continuation
to the next capsule's descriptor list. All capsules must use the FMP GUID and
persist-across-reset flag; the FMP populate-system-table prohibition remains.
The configured capsule, item, nested-capsule and embedded-volume/decompression
limits apply cumulatively across the entire stream. JSON and mixed-GUID
scatter/gather streams remain unsupported. The existing
`parse_uefi_fmp_scatter_gather` API retains its exact-one-capsule contract.

The result retains every descriptor's physical address and capture offset,
kind, Length and target physical address. Each data descriptor also records
its logical capsule offset and original capture-data offset. A logical range
crossing fragment boundaries maps to several data records; it must not be
represented by a single invented capture offset. The list result retains each
capsule's start in `capsule_logical_offsets` and its inventory in
`inventory.capsules`. Item and top-level embedded-volume offsets remain local
to that capsule: add the capsule's logical-stream offset before translating
through the data descriptors. Nested offsets retain their existing
parent-relative conventions. CLI labels distinguish capsule-local,
logical-stream and descriptor/data capture offsets, showing the first
256 descriptor records with an explicit omission count; the API retains all
records up to the descriptor cap. Existing item/nested output caps still apply.

This follows the descriptor Length/continuation/termination semantics in
[UEFI 2.11 UpdateCapsule](https://uefi.org/specs/UEFI/2.11/08_Services_Runtime_Services.html#updatecapsule).
It is offline inventory, not runtime UpdateCapsule processing or a firmware
update. Automatic physical-address discovery, live-memory access, signature
verification, and anti-rollback enforcement remain unsupported. FMP dependency
expressions are parsed and can be evaluated separately against an explicit
caller-supplied version inventory; that result does not authorize or apply an
update. The caller must keep the supplied capture bytes stable for the duration
of parsing.
The parser does not infer OS page size or certify physical page topology and
alignment requirements; repeated captured ranges remain inspectable under the
existing offline profile. No signature, freshness or firmware-applicability
decision is made.

### Sparse offline capture regions

The C++ API `parse_uefi_fmp_scatter_gather_regions` accepts up to 256
`UefiCapsuleCaptureRegion` entries, each pairing a physical base with a stable
byte span. Descriptor chains and data extents may point between those disjoint
regions. Region ranges must be nonempty, non-overlapping, and fit within the
cumulative 512 MiB capture and capsule-input budgets; each 16-byte descriptor
and each data extent must fit wholly in one region. Physical pointers remain
explicit and are never interpreted as live addresses. Returned block records
carry separate descriptor and data region indexes plus offsets local to those
regions, while `capture_region_bases` maps the indexes back to physical bases.
Capsule offsets remain in the gathered logical stream. The caller must keep
all region storage stable for the duration of parsing. The CLI currently takes
one flat capture file; multi-region maps are available through the C++ API.

## Contiguous capsule inventory

Run `hexlab_cli firmware inspect <path> --format uefi-capsule` to inventory one contiguous EFI capsule beginning at file offset zero. The CLI recognizes both FMP capsules and the UEFI JSON capsule envelope. For FMP, it reports the EFI capsule header, FMP header counts, embedded driver extents, and each FMP image descriptor with image type GUID, image index, image and vendor-code sizes, absolute file offsets, and version 2/3 hardware-instance and capsule-support fields. For JSON, it reports the capsule ID, version, payload size, and offset while preserving payload bytes as opaque data after validating their generic JSON syntax. To inspect an EFI_CAPSULE_TABLE-style list, pass each capsule as a separate path before the format option: `hexlab_cli firmware inspect <path1> <path2> --format uefi-capsule`. Lists accept same-GUID FMP capsules or same-GUID JSON capsules, up to 256 files. The parser applies the 512 MiB cumulative input and same-GUID checks; FMP lists also share the 4096 item and embedded-inventory budgets, while JSON lists share the 16 MiB JSON-validation budget. Each capsule's reported offsets are local to that input file.

Capsule rows retain the raw hexadecimal `flags` value and also print
`flag-names` for the standard `persist-across-reset`, `populate-system-table`,
and `initiate-reset` bits. Unknown and capsule-specific flag bits remain
available in the raw value. JSON capsules and nested FMP/JSON rows use the same
labels; the names describe header bits and do not imply that an update is safe
or applicable.

For version-3 FMP image headers, the CLI also names the defined
`ImageCapsuleSupport` authentication and dependency bits, reports the exact
source offset of that 64-bit field, and preserves unrecognized bits separately
from the raw value. If the authentication bit disagrees with recognition of a
standard PKCS#7 `EFI_FIRMWARE_IMAGE_AUTHENTICATION` prefix, it emits a bounded
per-item warning at the support-field offset. This is an inventory consistency
hint: an unknown certificate format is reported as unrecognized, and no update
is rejected or treated as trusted because of this warning. The bit definitions
follow [UEFI 2.11, section 23](https://uefi.org/specs/UEFI/2.11/23_Firmware_Update_and_Reporting.html)
and EDK II's [`FmpCapsule.h`](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Guid/FmpCapsule.h).

For a single contiguous FMP capsule, export one top-level update image with
`hexlab_cli firmware inspect update.cap --extract-item 0 --output image.bin
--format uefi-capsule`. The index is zero-based and addresses the parser's
top-level item table; embedded-driver entries are rejected. The extracted bytes
are the firmware image payload after any recognized authentication prefix,
dependency expression, and EDK II `MSS1` payload header. Vendor-code bytes are
not included. The original capsule and all recorded wrappers remain untouched.
The output is published through a same-directory temporary and refuses to
replace an existing path unless `--replace` is specified. The source input path
is protected from being selected as output. JSON capsules, multiple-input
lists, and scatter/gather captures are not eligible for item extraction. This
copies bytes only; it does not verify signatures, assess applicability, or
apply the firmware update.

The FMP parser accepts the standard 28-byte EFI capsule header or an extended header identified by `HeaderSize`, the FMP capsule GUID, FMP header version 1, and FMP image header versions 1 through 3. It checks declared bounds, ascending item offsets, descriptor sizes, cancellation, a 512 MiB input cap, and a 4096-item cap. The JSON parser validates the same generic capsule extent and the version-1 `EFI_JSON_CAPSULE_HEADER` (exact nonzero payload extent), then validates payload UTF-8 and JSON syntax. It accepts any JSON value because UEFI leaves the payload schema to the receiving firmware driver; platform-specific schema binding is not attempted. Validation is bounded to 16 MiB and 128 nested arrays/objects by default, with configurable limits and cancellation. For an extended EFI capsule header, the API and CLI report the exact opaque byte range between the fixed 28-byte header and `HeaderSize`; no assumptions are made about those extension bytes. The API also reports the number of input bytes after `ImageSize`, separately from the declared capsule extent. Malformed and unsupported structures return a diagnostic. Payload bytes, embedded drivers, and vendor data are never extracted or executed.

The FMP library also recognizes a nested FMP or JSON capsule when its known
capsule GUID starts exactly at an embedded-driver item or update-image payload
start (after any recognized authentication prefix). Nested FMP items are
recursively inventoried; JSON capsules retain only their validated envelope
and JSON header because their payload remains opaque. `UefiCapsuleItem::nested_capsules`
forms a tree. A nested record's `item_relative_offset` is relative to its parent
item, and child-item file offsets are relative to that nested capsule buffer.
`UefiNestedCapsule::size` is the nested header's declared `ImageSize`;
`candidate_size` is the full item/payload span passed to its parser, and
`trailing_size` reports bytes after `ImageSize` within that span. This keeps
the actual capsule extent distinct from available containing bytes. The CLI
prints these nested levels recursively with a shared cap of 320 capsule summary
rows and 4,096 item rows per command invocation. A malformed recognized nested candidate
marks that item's nested scan incomplete with a diagnostic; the containing
capsule and item remain available. Unrecognized bytes remain opaque without a
diagnostic. Nested parsing shares caller-provided limits across a capsule list:
64 nested capsules, four levels, and 128 MiB of candidate bytes by default.
Capsule bytes are still metadata only and are not applied or executed.

For FMP image payloads beginning with the standard `EFI_FIRMWARE_IMAGE_AUTHENTICATION` and PKCS#7 `WIN_CERTIFICATE_UEFI_GUID` prefix, the parser validates the certificate header extent and reports the monotonic count, certificate range, and certificate-data range. The reported payload offset skips this authentication prefix, while the descriptor's `image-size` continues to represent the full update-image size. It does not verify signatures, trust certificates, enforce monotonic freshness, or interpret certificate contents. Payloads that do not match the standard PKCS#7 certificate type remain opaque. This metadata follows the [UEFI 2.11 authentication structure](https://uefi.org/specs/UEFI/2.11/23_Firmware_Update_and_Reporting.html).

On Windows, `verify_uefi_fmp_authentication` uses Crypt32's detached-message
verification for every signer in a recognized authentication prefix. It
verifies the PKCS#7 signature over the original eight-byte MonotonicCount,
followed by the UpdateImage bytes after the authentication header, including
any dependency expression and optional `MSS1` header. The API reports a
separate cryptographic status per signer and retains provider error codes.
Verification bounds each PKCS#7 object to 64 MiB and 64 signers; the CLI
attempts at most 64 authenticated top-level items per command. Other platforms report
the provider as unsupported. This check does not validate a certificate
chain, revocation, signer authorization, monotonic freshness, capsule digest
policy, or applicability to a device, and it never applies or executes an
update. The detached-content order follows UEFI 2.11 section 23.3 and EDK II's
[FMP authentication description](https://github.com/tianocore/edk2/blob/master/FmpDevicePkg/Readme.md#capsule-authentication); the verifier uses Microsoft's
[`CryptVerifyDetachedMessageSignature`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptverifydetachedmessagesignature), whose default signer-certificate callback searches the message certificate store.

For a recognized PKCS#7 authentication prefix, `authentication_signed_image_offset`
and `authentication_signed_image_size` identify the UpdateImage bytes after the
optional dependency expression. The dependency expression has its own exact
range, and the monotonic count is reported separately; together these show the
capsule bytes described by UEFI's authentication input layout. The image span
includes an optional `MSS1` payload header because that wrapper is part of
UpdateImage, and excludes the separate vendor-code bytes. These offsets describe
the intended signed content only. `verify_uefi_fmp_authentication` performs
the platform-gated cryptographic coverage check; it does not establish trust
in the capsule.

After any authentication prefix, the parser recognizes the optional EDK II
`FMP_PAYLOAD_HEADER` when the `MSS1` signature is present. It validates the
declared header size and reports its range, firmware version, and lowest
supported firmware version. A lowest-supported version greater than the
payload firmware version is rejected as malformed during capsule parsing, so
invalid rollback metadata cannot pass through inventory without an explicit
policy-evaluation request. `firmware-image-offset` points past this wrapper;
embedded firmware-volume and nested-capsule scans begin there. The original
`payload-offset` remains the start of update data after authentication, so both
wrapper provenance and the contained firmware start are explicit. The header's
version fields are informational: this inventory does not enforce anti-rollback
policy or verify the update. Layout follows EDK II's
[`FmpPayloadHeader.py`](https://github.com/tianocore/edk2/blob/master/BaseTools/Source/Python/Common/Edk2/Capsule/FmpPayloadHeader.py).

For version-3 FMP image headers that set `CAPSULE_SUPPORT_DEPENDENCY`, the
parser reads the dependency expression immediately after any authentication
prefix and before an optional `MSS1` payload header. It validates the bounded
postfix instruction stream, operand types, UTF-16 version-name strings, final
`END`, and the optional leading `DECLARE_LENGTH` extent. The capsule item
retains the expression's file offset and byte size; its ordinary
`firmware-image-offset` continues to point past both wrappers. The expression
is parsed but never treated as trusted policy or executed during loading.

Call `evaluate_uefi_fmp_dependency_expression` with the expression byte span
and caller-supplied `UefiFmpImageVersion` records to evaluate it. The evaluator
implements all UEFI FMP dependency opcodes and uses three results:
`satisfied`, `unsatisfied`, and `indeterminate`. A missing GUID resolves to
unsatisfied only when the caller declares its version inventory complete; an
incomplete inventory or conflicting duplicate version entries remain
indeterminate. This avoids treating unavailable device state as a negative
match. Evaluation is capped at a 1 MiB expression, 65,536 instructions, and
65,536 version records, and supports cancellation. It does not discover live
FMP instances, determine whether the supplied version inventory is complete,
authenticate a signed dependency expression, or apply an update. The caller
must supply trustworthy current versions and the exact expression span
retained by the parser.
Opcode encoding follows [UEFI 2.11 section 23.2](https://uefi.org/specs/UEFI/2.11/23_Firmware_Update_and_Reporting.html#dependency-expression-instruction-set); capsule wrapping follows EDK II's [`CapsuleDependency.py`](https://github.com/tianocore/edk2/blob/master/BaseTools/Source/Python/Common/Uefi/Capsule/CapsuleDependency.py).

The CLI exposes this evaluator only when requested:

```text
hexlab_cli firmware inspect update.cap --fmp-evaluate-dependencies \
  --fmp-image-version 12345678-1234-5678-90ab-cdef01234567=0x20 \
  --fmp-dependency-inventory-complete --format uefi-capsule
```

Repeat `--fmp-image-version GUID=VERSION` for caller-supplied current image
facts; each argument is capped at 256 characters, versions accept decimal or
`0x` hexadecimal, and up to 65,536 rows are accepted. Without
`--fmp-dependency-inventory-complete`, references to absent
GUIDs remain indeterminate. Declaring the inventory complete makes absent
GUIDs unsatisfied; conflicting duplicate versions remain indeterminate. The
CLI evaluates at most 4,096 top-level dependency-bearing FMP payloads and
reports omitted evaluations. Each expression remains subject to the 1 MiB
and 65,536-instruction evaluator limits. This option requires contiguous FMP
capsule input; scatter/gather and JSON inputs are rejected for this mode, and
item extraction cannot be combined with it. Nested FMP payload expressions
are not evaluated by this CLI pass. No versions are discovered from files,
firmware, or the host system.

FMP capsules setting `CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE` are rejected as malformed, as required by UEFI 2.10 §23.3.3. A capsule that sets `CAPSULE_FLAGS_INITIATE_RESET` without `CAPSULE_FLAGS_PERSIST_ACROSS_RESET` is also rejected, following the standard flag dependency. The three reserved bytes in every versioned FMP image header must also be zero.

For the supported FMP and UEFI JSON capsule GUIDs, specification-defined flag bits 19–31 are reserved and are rejected when set. Bits 0–15 are defined by the capsule GUID and remain opaque to this parser; bits 16–18 are checked according to the format-specific rules above. This bounded validation does not verify signatures, authentication, or firmware-specific policy.

The C++ API accepts a bounded EFI_CAPSULE_TABLE-style list of independent contiguous FMP or JSON capsule buffers. The CLI accepts the same list as multiple file paths. All entries must use the same capsule GUID and stay within the 512 MiB cumulative input and 256 top-level capsule limits. FMP lists additionally apply the 4096 cumulative top-level item limit and shared embedded-inventory budgets. JSON lists validate each payload's generic JSON syntax under a shared 16 MiB payload budget; firmware-specific schemas remain opaque. A mixed-GUID list is malformed. Item and payload offsets are local to their corresponding buffer. Nested parsing is limited to known capsule GUIDs at item/payload starts; the parser does not search arbitrary offsets, parse runtime scatter/gather block descriptors, validate signatures or payload authentication, decode firmware-specific payload formats, or update firmware.

FMP update-image payloads and embedded-driver items are also scanned for embedded PI firmware volumes. The inventory reports each volume's capsule-buffer offset, size, file-system GUID, revision, header-checksum state, and file/section counts. These offsets point into the capsule bytes that contain the item (and are therefore local to a nested capsule when one was recognized); the payload is not copied or modified. Each capsule is bounded to 64 item-payload scans, 64 discovered volumes, 65,536 files, 65,536 sections, and 128 MiB of decompressed section data across all item payloads. Capsule lists share those budgets across all inputs. Each scan gets at most one 64th of the decompression budget, bounding work even when a malformed earlier payload prevents accounting for partial decompression. An item with no recognized FFS2/FFS3 volume is a complete scan with zero results. If a parser error or exhausted budget prevents a scan from completing, capsule parsing remains available and marks that item's embedded-volume scan incomplete with a diagnostic. Once a volume is found, its FFS files and supported compressed-section streams are inventoried by the PI parser; firmware volumes located only inside decoded section contents are not yet linked or reported. Embedded drivers are inventoried only; their PE/TE images are not loaded or executed, and PEI/MM dispatch and execution remain unsupported.

The layout follows the [UEFI 2.11 FMP and JSON capsule structures](https://uefi.org/specs/UEFI/2.11/23_Firmware_Update_and_Reporting.html); the table's array count and same-GUID constraint follow the [UpdateCapsule() definition](https://uefi.org/specs/UEFI/2.10/08_Services_Runtime_Services.html#updatecapsule). The FMP parser was also compared with EDK II's [FmpCapsule.h](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Guid/FmpCapsule.h), [DxeCapsuleLibFmp](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Library/DxeCapsuleLibFmp/DxeCapsuleLib.c), and [CapsuleDump](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Application/CapsuleApp/CapsuleDump.c). The [Ghidra Firmware Utilities](https://github.com/al3xtjames/ghidra-firmware-utils) document a related hierarchical loader for UEFI firmware volumes and nested FFS files/sections. That project does not describe FMP capsule parsing, so the FMP structures here follow the UEFI and EDK II references directly; only the general inventory practice of retaining nested item boundaries and metadata was relevant.

### Advisory FMP anti-rollback evaluation

`evaluate_uefi_fmp_anti_rollback` compares an MSS1 update payload's firmware version with the installed image's lowest-supported version, matched by image-type GUID. Callers provide `UefiFmpInstalledImage` records; a missing or conflicting record, unknown installed rollback floor, or incomplete inventory yields `indeterminate`. An absent match is reported as `not_installed` only when the caller marks the inventory complete. Candidate lowest-supported versions greater than the candidate firmware version are rejected as malformed. Evaluation is bounded to 65,536 records and supports cancellation.

The CLI accepts repeated `--fmp-installed-image GUID=VERSION,LOWEST` options and `--fmp-inventory-complete`. Versions are decimal or `0x` hexadecimal; `-` means the installed floor is unknown. For example:

```text
hexlab_cli firmware inspect update.cap --fmp-installed-image 12345678-1234-5678-90ab-cdef01234567=0x20,0x10 --fmp-inventory-complete --format uefi-capsule
```

The output is advisory and evaluates the candidate against the caller-supplied current inventory; it does not authenticate the capsule, verify inventory provenance, consult live firmware, or apply the update. The MSS1 layout follows EDK II's [`FmpPayloadHeader.py`](https://github.com/tianocore/edk2/blob/master/BaseTools/Source/Python/Common/Edk2/Capsule/FmpPayloadHeader.py); the rollback floor field is specified by the FMP image payload header in [UEFI 2.11, section 23](https://uefi.org/specs/UEFI/2.11/23_Firmware_Update_and_Reporting.html).
