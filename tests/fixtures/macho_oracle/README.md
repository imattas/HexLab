# Mach-O differential fixtures

`macho_oracle` compiles these original freestanding sources with pinned test-only
Clang, links x86-64 and arm64 dylibs/executables with `ld64.lld`, and compares
HexLab's original loader with observed LLVM output. It never executes a Mach-O
input. Objects cover i386, x86-64 and arm64; the assembly sources include i386
scattered/pair and x86-64 subtractor/PC-relative relocation records. The separate
compiler data-region fixture is `../macho_guard_x64.s`.

The Python runner creates FAT32/FAT64 containers in both byte orders and thin
literal headers in both widths/orders. Every selected universal child is
compared against LLVM's interpretation of its exact compiler-produced bytes.
For ordinary universal envelopes it also checks LLVM's ordered architecture,
offset, size and alignment projection. Swapped universal envelopes are outside
LLVM23's recognition: their literal descriptor expectations and selected-child
comparisons are recorded separately. LLVM normalizes thin magic and masks CPU
subtype capabilities in readobj; the runner combines objdump's capability
column with readobj's subtype and separately checks the expected byte order.

Header/command extents, segments, sections, original symbol/relocation words,
physical source records, object section domains, dynamic tables, library paths
and versions, classic dyld emissions, export addresses, chained headers/imports/
starts/page starts/raw pointers and static associations all have independent
comparisons. Literal source-word checks use offsets obtained from LLVM, rather
than trusting HexLab's source pointers. Twelve semantic projection mutations
must fail the verifier. Both loaders must reject truncated/invalid command
envelopes; an unknown command must retain explicit partial HexLab metadata.

`tools.json` pins binary identities. Missing tools, hash/version changes and
comparison mismatches fail; they cannot skip the suite. Each successful report
records source/tool/probe/runtime/input hashes and exact commands/output hashes.
Raw outputs remain alongside it. A failed run removes any stale passing report
and writes `failure.json`. LLVM's observed i386-linking rejection is checked;
i386 compiler objects still receive full metadata comparisons.

These are static format and metadata comparisons. They do not establish runtime
linking, authenticated-pointer behavior, Mach-O execution, complete instruction
decoding, debugger support or IDA parity. Recovery/cache/native/durable-project
tests provide separate evidence and remain part of the full gates.
