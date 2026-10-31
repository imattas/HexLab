# CLR ManifestResource metadata and embedded data

`parse_managed_resources` reads the ECMA-335 ManifestResource table (II.22.38)
and flags (II.23.1.9) from a CLR metadata root ([ECMA-335, 5th edition]
(https://www.ecma-international.org/wp-content/uploads/ECMA-335_5th_edition_december_2010.pdf)).
It retains each resource token, name, visibility flags, metadata-root-relative
row offset, data offset, and Implementation coded index.
Nil Implementation identifies an embedded resource. File-backed resources
also retain the referenced File name and `ContainsNoMetadata` flag.
AssemblyRef-backed resources retain the referenced assembly name, four-part
version, neutral-or-named culture, flags, and PublicKeyOrToken blob index.
They also retain the AssemblyRef `HashValue` blob and the owning Assembly's
`HashAlgId` when present.
ExportedType implementations retain their metadata token. The default parser
retains external identities but does not resolve files or assemblies.

`inspect_managed_resources` performs the same table validation on a loaded PE,
then reads embedded resource records from `IMAGE_COR20_HEADER.Resources`. It
checks the directory pair, length-prefix range, declared payload extent, and
image mapping before returning bytes after the four-byte little-endian length
prefix. Resources with external implementations have an empty `payload` and
remain metadata-only unless the caller selects the supplied-input overload.

The overload taking `ManagedResourceInput` resolves external resources only
against caller-supplied byte stores and, when required, loaded PE images. It
never searches a directory or probes the host. File implementations require an
exact supplied `File.Name`, a unique content match, and a matching
`File.HashValue` computed with the owning Assembly's `HashAlgId`. SHA-1
(`0x8004`) and SHA-256 (`0x800c`) are supported; absent hashes and other
algorithms remain unresolved. `ContainsNoMetadata` files expose their bounded
raw payload; metadata-bearing files require a unique same-name embedded
ManifestResource row. AssemblyRef implementations require a unique supplied
assembly with matching name, culture, version, flags, and public-key identity,
including token derivation from a supplied full strong-name key. If the
AssemblyRef row has a nonempty `HashValue`, its supplied candidate must also
match that hash under the owning Assembly's `HashAlgId`; an absent hash
preserves identity-only matching. SHA-1 and SHA-256 are supported for this
check. The candidate must then contain a unique same-name embedded resource
with the exact ManifestResource offset. Nested external providers are not
followed.
Missing, ambiguous, unsupported-hash, and mismatched-hash cases retain an
explicit resolution state and diagnostic without discarding metadata.

The resolver accepts at most 256 inputs and 512 MiB of cumulative input bytes,
and defaults to a 64 MiB aggregate resolved-payload budget. The project CLI
accepts an explicit UTF-8 path list with one caller-selected input per line:
`hexlab_cli project managed-resources <project> --inputs-list <paths.txt>`.
Relative entries are resolved only against the list file's directory. No
search paths are inferred. `--json` emits each resource's resolution state,
diagnostic, and (when present) implementation hash algorithm, full hash byte
count, and at most the first 32 hash bytes in hexadecimal. Text output uses
the same bounded hash prefix. For decoded `.resources` payloads, both text and JSON output
include a bounded record summary with type code, value kind, type name,
support status, payload-relative data span, and decoded scalar bits or string
text when available. Record byte contents are never deserialized or emitted.
The CLI emits at most 4,096 record summaries across the command; each resource
reports its omitted detail count, and overall completeness becomes false when
details are omitted.

For an embedded payload beginning with the .NET resources magic, inspection
also parses ResourceManager header version 1 and RuntimeResourceSet version 2.
It validates the header strings, type-name strings, aligned hash/position
tables, signed hash ordering and each hash against its UTF-16LE resource name,
name-section offsets, UTF-16LE resource names, UTF-8 strings, and each record's
data extent. `ManagedResource::payload` always retains the original
bytes. Parsed records are exposed in `ManagedResource::records`; `data_offset`
and `data_size` on each record refer to byte spans in that owning payload.
Primitive values (null, strings, Boolean, character, integer, floating point,
decimal, DateTime, and TimeSpan) and byte arrays/streams are identified by
their resource type code. Scalar records expose the low 64 serialized bits in
`scalar_bits`; their complete original bytes, including 128-bit decimals, stay
available through the payload span. Byte-array and stream values point to
their raw payload bytes. Strings are returned as validated UTF-8. User-defined type records retain their type name
and opaque serialized bytes with `supported == false`; reserved or unknown
type codes are likewise marked unsupported. No BinaryFormatter data is
deserialized. External resource bytes are available only through the explicit
supplied-input overload described above.

Nonstandard ResourceReader/ResourceSet implementations and unsupported
versions are explicitly reported through `payload_format` and
`payload_diagnostic`, leaving the original payload available. Malformed
recognized formats return an error instead of a partial record catalog.

The metadata root is capped at 64 MiB and at 65,536 ManifestResource rows.
Names are limited to 4,096 bytes each and 8 MiB total. Embedded data inspection
accepts a Resources directory up to 256 MiB, at most 16 MiB per resource and
64 MiB of payload bytes total. Invalid visibility flags, heap indexes, coded
indexes, duplicate names, invalid File/AssemblyRef row layouts or identity
heaps, nonzero File-backed offsets, row extents, or embedded data extents fail
explicitly; oversized resources return a resource-limit
error rather than a partial payload. The `.resources` reader caps entries at
65,536, type names at 4,096 / 4 MiB total, resource names at 4 MiB total, and
each encoded string at 1 MiB. It requires valid UTF encodings and bounded,
non-overlapping section offsets.

The parser follows the documented runtime layout implemented by Microsoft's
[ResourceReader](https://source.dot.net/System.Private.CoreLib/src/runtime/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceReader.Core.cs.html),
[ResourceWriter](https://source.dot.net/System.Resources.Writer/src/runtime/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceWriter.cs.html),
and [resource type codes](https://source.dot.net/System.Private.CoreLib/src/runtime/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceTypeCode.cs.html).
The name-hash algorithm follows Microsoft's
[FastResourceComparer](https://source.dot.net/System.Private.CoreLib/src/runtime/src/libraries/System.Private.CoreLib/src/System/Resources/FastResourceComparer.cs.html).
