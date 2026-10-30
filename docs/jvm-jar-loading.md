# JVM JAR loading

HexLab can inventory a Java JAR with `hexlab_cli jar list <package.jar>` and
inspect one selected class with `hexlab_cli jar inspect <package.jar> --member
<index>`. Member indexes follow central-directory order. The class inspection
path extracts the selected entry into bounded memory, validates its declared
uncompressed size and CRC-32, then sends those bytes through the ordinary JVM
class-file loader.

The reader supports single-volume and split-volume ZIP32 and ZIP64 archives,
stored members (method 0), and raw DEFLATE members (method 8). For split
archives, callers pass the volumes in disk-number order to the volume-aware
`read_jar_archive` overload; the existing one-storage overload remains the
single-volume convenience path. The reader maps ZIP32 and ZIP64 disk-relative
central-directory and local-header offsets through volume boundaries, and
allows compressed member data to span volumes. ZIP64 end records and sentinel
entry sizes/offsets are validated with their required ZIP64 extra-field
values and supplied volume count. Encrypted
members, unsupported general-purpose flag combinations, data that overlaps
the central directory, and other compression methods are inventoried where
possible but cannot be extracted. Entries using general-purpose bit 3 must
include a data descriptor after their compressed bytes; the reader checks its
CRC-32 and 32-bit or ZIP64 sizes against the central directory and rejects a
missing, inconsistent, or central-directory-overlapping descriptor. The
optional descriptor signature is accepted. DEFLATE extraction requires consuming the
entire compressed extent and producing exactly the declared output length
before CRC verification. Inventory is bounded to 512 MiB of archive bytes,
65,536 volumes, and 100,000 entries. Names are limited to 4 KiB, a member may
expand to at most 128 MiB, and total declared uncompressed content is capped
at 4 GiB. Class extraction verifies the output length and CRC before parsing.

The class-file parser validates that `ConstantValue` appears only on static
fields, as well as attribute placement, uniqueness,
exact length, constant-pool kind, and compatibility with the field descriptor.
Field metadata retains the constant-pool tag and raw numeric bits; string
constants retain their resolved modified-UTF-8 text. The CLI reports these
values beside their fields, using hexadecimal bits for numeric values so NaN
payloads and signed zero remain unambiguous.

For Java 9 or newer `module-info.class` files, the class parser retains the
`Module`, `ModulePackages`, and `ModuleMainClass` attributes as typed metadata.
Module requires, exports, opens, uses, and provides entries remain in source
attribute order, with their flags, target modules, versions, and provider names
preserved. Constant-pool references are checked for the required Module,
Package, Class, and UTF-8 kinds; malformed lengths, duplicate entries, reserved
flag bits, and excessive entry counts are rejected. This is classfile metadata
retention only: it does not link modules, resolve module paths, or prove that
required modules and provider classes are present.

This first JAR path inspects one class at a time. It does not resolve
multi-release JAR selection, manifests, class paths, dependency graphs, or
cross-class symbols. No filesystem extraction is performed, so member names
are displayed as archive paths and are never used as output paths.

The CLI accepts an ordinary package path and discovers standard split-ZIP
volumes named `<base>.z01`, `<base>.z02`, …, followed by `<base>.zip`, when
they are present beside that path. Numbered volumes must be contiguous from
`.z01`; a gap is reported as an input error. For nonstandard names or layouts,
pass the complete volume list explicitly and repeat `--volume` in disk-number
order, for example `hexlab_cli jar list --volume first.bin --volume second.bin`.
When using explicit volumes, do not also pass the package path. The same forms
work with `jar inspect`, with `--member <index>` included for the selected
class. Both discovery and explicit input are bounded to 65,536 volumes, and
the loader enforces the 512 MiB combined archive-byte limit.
