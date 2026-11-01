# Legacy x86 decimal adjustment

The typed decoder recognizes DAA (`27`), DAS (`2f`), AAA (`37`), and AAS (`3f`)
in 16- and 32-bit modes. Long mode and LOCK are invalid; repeat prefixes stay
outside the typed subset. Size and segment prefixes retain fixed AL/AH effects.
AAA/AAS read AL, AH, and AF; DAA/DAS read AL, CF, and AF. All replace the six
arithmetic flags, including undefined outputs.

`evaluate_x86_decimal_adjust` returns AX and defined flag bits. AAA/AAS use
full-width AX correction followed by low-nibble masking; only CF/AF are defined.
DAA/DAS preserve AH and define CF/AF/PF/ZF/SF. DAS retains low-correction borrow.
Decoded adapters validate bytes and effects before evaluation.

The dedicated decompiler lift emits AL/AH/FLAGS expressions and explicit merged
AX/EAX aliases. This keeps later wider-register reads synchronized with the
byte writes while preserving AH for DAA/DAS and EAX[31:16] in both legacy
modes. It preserves unaffected FLAGS bits and represents undefined status bits
with unknown values. It does not impose a valid-BCD precondition or assume
undefined flags are zero.
Condition tracking exposes CF after AAA/AAS and CF/PF/ZF/SF after DAA/DAS;
branches requiring undefined flags remain opaque.
AAM/AAD remain in their existing separate decoder/evaluator/lifter.

Instruction behavior follows [Intel SDM Volume 2A, AAA/AAS/DAA/DAS](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf).
Machine-state execution, historical pre-IA-32 CPU differences, and decimal
sequence recovery remain unsupported. Validation was compile-only; no tests ran.
