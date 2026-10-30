# PowerPC compare semantics

`evaluate_ppc_compare_instruction` evaluates decoded PPC32/PPC64 `CMP`/`CMPL`
and `CMPI`/`CMPLI` forms into the selected four-bit CR field. Signed forms
interpret operands at the decoded 32- or 64-bit width; logical forms compare
unsigned bit patterns. The result encodes LT/GT/EQ and caller-supplied XER.SO.

The decoder records XER as a read dependency because each compare copies SO
into the CR field. The helper validates operands and those effects, and uses
the decoded signed or unsigned immediate. It returns the CR nibble only;
source sampling and CR/XER state commit remain caller-owned.
