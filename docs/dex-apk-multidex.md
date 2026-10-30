# Android APK multidex loading

`load_android_dex_archive` reads APK ZIP metadata with the existing bounded
ZIP reader, selects root entries named `classes.dex`, `classes2.dex`, and so
on, and loads them in numeric order. The sequence must start at `classes.dex`
and be contiguous; gaps and duplicate canonical names are rejected. Unrelated
ZIP entries and noncanonical `.dex` names are ignored.

Selected members are extracted with stored or raw-DEFLATE support and their
declared size and CRC-32 are verified before DEX parsing. Each returned row
retains its entry name and ZIP central-directory index, physical APK data
offset, compressed and uncompressed sizes, CRC, and compression method. A DEX
041 entry may contain multiple logical headers; those return as separate rows
with a logical-member index and use the existing DEX 041 container loader.

Defaults cap the ZIP input at 512 MiB, selected uncompressed DEX bytes at
512 MiB total, each extracted ZIP member at 128 MiB, and parsed logical members
at 256. Across all returned images, retained metadata is capped at two million
rows, 64 MiB of string capacity, 256 MiB of vector/string capacity, and one
million class/interface/declared-member rows. The ZIP reader supports
stored and DEFLATE entries; encrypted entries and unsupported compression or
ZIP flags remain unsupported. The CLI command `hexlab_cli dex apk <path>` shows
each loaded logical member and its APK provenance; `--json` emits the same
summary as JSON. This does not parse the Android manifest, resolve classes
across DEX entries, apply multidex runtime ordering rules beyond numeric entry
names, or run the Android verifier.
