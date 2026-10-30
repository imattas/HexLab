# DEX string and member identifier catalogs

`DexMetadata` retains every validated string, field ID and method ID in original
table-index order, including references to members not declared by any local
class. This extends the existing declared-class/member summaries and prototype
metadata; it does not load external classes or perform runtime member lookup.

`strings` stores the parser's decoded UTF-8 strings, preserving embedded NULs.
The parallel `string_sources` table retains each `string_id_item` file offset,
the referenced `string_data_item` file offset, its full encoded byte extent
(ULEB128 length, modified-UTF-8 payload and terminator), and its declared UTF-16
code-unit count. The original modified-UTF-8 bytes remain available through the
source image; this change does not expand the accepted string grammar.

Each `field_identifiers` row retains declaring Type ID, field Type ID, name
String ID and the exact eight-byte identifier row's file offset. Each
`method_identifiers` row retains declaring Type ID, prototype ID, name String
ID and source row offset. Name indexes resolve through `strings`, type indexes
through `type_descriptors`, and prototype indexes through the existing shared
prototype return/parameter catalogs. Annotation element names, encoded string
constants, field/method references and method-handle targets can therefore be
interpreted against retained local tables without inventing definitions.

Identifier row storage and decoded string bytes share a 64 MiB model budget,
charged before allocation and while decoding strings. Existing identifier
counts, table/map extents, index bounds, UTF-16 ordering, descriptor/name rules
and per-string limits remain enforced. Cancellation is checked during string
and member-catalog construction. Class, debug, annotation and encoded-value
metadata retain their existing separate budgets.

The CLI inspection and project metadata formatter shows up to 128 rows from
each new catalog, reports omitted row counts, and includes identifier/data
source offsets. String/name previews escape controls, quotes and backslashes;
they stop at a UTF-8 boundary after at most 160 input bytes and label
truncation. API strings remain complete.

Type and string pools move into the result only after code-segment labels have
been formed. This also fixes the previous ordering in which segment label
construction accessed the moved type table. Metadata is rebuilt from source on
project reopen; no standalone DEX metadata serialization was added.

Full verifier semantics, external resolution, optimized-container handling and
multi-member DEX 041 remain unsupported. The metadata layout follows the
[AOSP DEX format's string, field and method identifier definitions](https://source.android.com/docs/core/runtime/dex-format).
