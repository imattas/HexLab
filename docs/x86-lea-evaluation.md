# x86 LEA evaluation

`evaluate_x86_lea_instruction` computes the effective offset for decoded LEA
base/index forms with 32- or 64-bit address size. The caller supplies the base
and index GPR values through a callback. The evaluator applies scale,
displacement, and address-width wrapping, then truncates or zero-extends to the
destination width. LEA does not access memory, and segment bases are ignored.

The helper rejects 16-bit address-size forms and IP-relative operands. It does
not sample registers itself, access memory, apply segment bases, or commit the
destination. Register-state and other address-form handling remain
caller-owned.
