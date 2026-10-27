# JVM JAR loading

HexLab can inventory a Java JAR with `hexlab_cli jar list <package.jar>` and
inspect one selected class with `hexlab_cli jar inspect <package.jar> --member
<index>`. Member indexes follow central-directory order. The class inspection
path extracts the selected entry into bounded memory, validates its declared
uncompressed size and CRC-32, then sends those bytes through the ordinary JVM
class-file loader.

The reader supports single-disk ZIP32 and ZIP64 archives, stored members
(method 0), and raw DEFLATE members (method 8). ZIP64 end records and sentinel
entry sizes/offsets are validated with their required ZIP64 extra-field
values. Split archives, encrypted members, data that overlaps the central
directory, and other compression methods are unsupported. Inventory is
bounded to 512 MiB of archive bytes and 100,000 entries. Names are limited to
4 KiB, a member may expand to at most 128 MiB, and total declared uncompressed
content is capped at 4 GiB. Class extraction verifies the output length and
CRC before parsing.

The class-file parser validates that `ConstantValue` appears only on static
fields, as well as attribute placement, uniqueness,
exact length, constant-pool kind, and compatibility with the field descriptor.
Field metadata retains the constant-pool tag and raw numeric bits; string
constants retain their resolved modified-UTF-8 text. The CLI reports these
values beside their fields, using hexadecimal bits for numeric values so NaN
payloads and signed zero remain unambiguous.

This first JAR path inspects one class at a time. It does not resolve
multi-release JAR selection, manifests, class paths, dependency graphs, or
cross-class symbols. No filesystem extraction is performed, so member names
are displayed as archive paths and are never used as output paths.
