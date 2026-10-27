# PE resource directories

The PE loader parses data-directory entry 2 into `ImageMetadata::pe->resources`. Each `PeResource` represents a language-level leaf and records the type, name, and language identifiers. An identifier contains either its numeric ID or its UTF-16 name converted to UTF-8. The leaf also retains its data RVA, byte size, code page, source locations for the directory entry and data entry, and file spans backing the payload.

The traversal is bounded by the PE directory extent, the image mapping, a one-million-entry budget, and a maximum nesting depth. Cyclic directory references, malformed UTF-16, invalid named/ID grouping, data entries outside the directory, nonzero reserved fields, and payloads outside initialized image bytes produce a directory diagnostic and mark metadata incomplete. A malformed resource directory does not prevent loading the executable or inspecting other metadata.

The current public model handles the conventional three-level type/name/language resource hierarchy. Deeper trees and data leaves at other levels are reported as malformed rather than flattened ambiguously. Resource payload bytes are not copied into the metadata; their RVA, size, and source spans allow callers to read them through the loaded image.

The desktop PE metadata workspace includes a read-only Resources page. It displays
the type, name, language, data RVA, byte size, code page, data-entry file offset,
payload file offset, and source record index. The virtual table displays at most
4,096 entries and reports when rows were omitted. Selecting a nonempty resource
navigates the main byte listing to the first file-backed payload span, without
copying the payload into the view. Resources without a file-backed span and
zero-length resources remain listed but have no payload navigation target.

For numeric `RT_VERSION` (type ID 16), the loader recognizes the canonical
`VS_VERSION_INFO` root and its `VS_FIXEDFILEINFO` value. It retains the four
16-bit file-version and product-version components, file flags, OS/type fields,
and file-backed provenance for the fixed record. Parsing reads at most the
first 4 KiB of the resource and only publishes the structured record when the
root key, bounds, and fixed-info signature match. Other version-resource
layouts remain available through their raw payload spans. `hexlab_cli inspect`
prints decoded file and product versions, capped at 256 rows.

For numeric `RT_MANIFEST` (type ID 24), the loader extracts the root
`assemblyIdentity`, identities beneath `dependentAssembly`, and
`requestedExecutionLevel`/`uiAccess` attributes. UTF-8 (with an optional BOM)
and UTF-16LE manifests are inspected. The XML scanner is bounded to 1 MiB per
resource, 16 MiB across the image, 64 levels, 16,384 tags, and 64 attributes per
tag. It resolves only predefined XML entities and numeric character references;
DTDs and external entity expansion are not processed. Unknown XML content is
skipped while malformed recognized syntax marks the structured record partial.
Raw payload spans remain available for unsupported encodings and other
manifest metadata. `hexlab_cli inspect` reports decoded identities and
execution-level requests with bounded output; these fields are descriptive and
do not imply that Windows will grant the requested access level.
