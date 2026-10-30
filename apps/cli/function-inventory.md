# CLI function inventory

`hexlab_cli functions <path> [input options] [analysis options] [--limit N]
[--json]` runs the same function-recovery engine used by pseudocode output and
prints a bounded inventory without requiring disassembly text.

The text form reports total recovery status and, for each returned function,
its entry, an exported name when available, basic-block and instruction counts,
chunk count, outgoing-call count, thunk status, and whether recovery was
complete. JSON uses schema `hexlab.function-inventory.v1` and additionally
includes chunk extents, seed kinds, stop reasons, and bounded call details.
The JSON `complete` field reports the recovery engine's completeness;
`truncated` reports whether `--limit` omitted function rows. Calls are capped at
100,000 details per report; each function emits at most 256 chunk, seed, and
stop details and includes corresponding total/omitted counts.

`--limit` defaults to 10,000 and accepts 1 through 100,000. The command also
accepts normal input options such as `--format`, `--slice`, `--pdb`, and raw
image mapping options, plus function analysis limits such as
`--instruction-budget`. `--show-strings` is not supported by this report.

Exit status is 0 when all discovered functions are returned and recovery is
complete, 3 when recovery is partial, the function limit truncates the list,
or no functions are found, and 1 for load or recovery errors. Invalid command
arguments return 2. Diagnostics remain on stderr, so JSON stdout stays one
parseable document.
