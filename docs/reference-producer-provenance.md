# Dataflow reference producer provenance

HexLab retains bounded instruction-level dependencies for x86/x64 dataflow
references. An edge `A depends on B` means instruction A used a value produced
by instruction B while deriving the reference target. This adds a real
predecessor graph to the existing flat producer summary.

The propagation tracks the latest producer for each known register value and
tracked pointer-sized memory value. Copies, address formation, arithmetic,
loads, and stores connect the current definition to its input producers. At a
control-flow join, equal values retain the alternative producer tails; those
graphs are marked ambiguous. Values that disagree are discarded by the
existing must-analysis, so the provenance graph does not claim a target for
them.

Each reference graph is capped at 64 producer nodes, 128 edges, and 32 levels.
The analysis also caps its shared parent map at 65,536 nodes and 262,144 edges.
Depth, size, or shared-map exhaustion sets `truncated`. A cycle is detected
during graph materialization, marked, and omitted from the returned edges.
The older flat list remains available for existing clients.

`ReferenceIndex::producer_graph(ReferenceId)` returns the graph for one
reference. The desktop References detail panel renders dependency edges and
labels ambiguous, cyclic, or truncated results. The derived-analysis engine
fingerprint was advanced so old flattened-only cache entries are recomputed.
Reference payload version 13 introduced the graph; version 15 retains immediate
operand records and continues to decode versions 7 through 14. The canonical
reference identity remains based on the pre-graph record fields.

Version 15 also preserves immediate operands found on the reference instruction
and its bounded producer instruction chain. Each entry retains the instruction
identity, operand index, decoded value, encoded/effective widths, and signedness.
The desktop detail panel shows these literals alongside dependency edges so a
user can inspect the constants that participate in address construction.
Immediate records are capped at 32 per reference; the graph is marked truncated
when more are available. Earlier payload versions remain readable and are
recomputed under the updated derived-analysis fingerprint. These records retain
decoded literal evidence; relocation and dyld origins continue to use their
format-specific provenance records.

RISC-V RV32/RV64 address propagation also emits this graph for its resolved
register-relative references. LUI/AUIPC definitions, ADDI/ORI address
construction, JALR targets, and validated memory operands carry dependencies
from each instruction to the prior address producer. A full-width static
pointer load continues the chain only when its slot is file-backed, readable,
unrelocated, and contains a pointer to a mapped address. Equal address values
at a CFG join merge alternative producer paths and mark the graph ambiguous;
conflicting values discard the address fact and its ancestry. Calls and
unknown register writes clear affected facts. RISC-V graphs use the same
64-node, 128-edge, and 32-level output limits, and their carried state marks
truncation when it reaches those bounds.

The shared non-x86 producer pass also materializes a bounded dependency chain
for resolved AArch64, A32/Thumb, MIPS32/MIPS64, PPC32/PPC64, and NMOS 6502
operands. Each reference keeps its exact source instruction and operand index,
while the graph links that consumer to the latest validated register producer
and follows the ordered producer IDs through their causal chain. On 6502, the
producer state is limited to A, X, and Y; immediate loads, register transfers,
and recognized single-source arithmetic/increment forms can feed references
that the independent 6502 address evaluator already resolved. The graph does
not resolve new effective addresses by itself, and unknown register writes
invalidate their prior producer. Proven PPC32/PPC64 register `ADD` and `SUBF`
definitions also participate after their architecture-specific evaluator
proves both inputs and the result. These chains are limited to 32 producer IDs
and 128 edges. They describe instruction ancestry; they do not claim
relocation-symbol detail or represent an immediate constant as a separate
graph node. Relocation-backed references continue to use their existing
format-specific provenance.

The derived-analysis fingerprint advances again for this non-x86 graph
generation, so cached reference results without these graphs are recomputed.
The 6502 producer graph addition advances that fingerprint as well.
The reference payload format and reference identity remain unchanged.

MIPS64 address propagation recognizes the dedicated N64 ADDI/ADDIU word
opcodes, including their 32-bit result sign extension, and register ADD/ADDU,
SUB/SUBU, DADDU, and DSUBU when both source values are proven. Trapping ADD
and SUB produce a value only when their signed 32-bit operation cannot
overflow. Resolved branch and memory references can therefore retain these
definitions as their producer chain; arithmetic that wraps ambiguously across
the address domain remains unresolved. The function-analysis fingerprint is
advanced so cached reference results are recomputed with this propagation.
