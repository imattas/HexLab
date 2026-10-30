# RISC-V Zicsr evaluation

`evaluate_riscv_csr_instruction` evaluates decoded `CSRRW`, `CSRRS`, `CSRRC`
and immediate `CSRRWI`, `CSRRSI`, `CSRRCI` forms for RV32 or RV64. It returns
the old CSR value for a nonzero `rd`, the resulting CSR bit pattern, and flags
indicating whether each destination is written. Set/clear with a zero source
is a CSR read with no write; `CSRRW` still writes when its source is zero.
Register `x0` is treated as a zero source.

The helper validates the decoder's operand, access, and read/write facts. The
caller provides the old CSR value and register-source value, and remains
responsible for privilege/CSR availability checks and committing results.
Architectural CSR side effects and trap delivery are not modeled.

`check_riscv_csr_privilege` adds a separate check for the CSR-address
minimum-privilege convention. It extracts CSR address bits 9:8 as U, S, H, or M
and reports whether the caller-supplied current privilege is that level or
higher. It accepts only structurally valid decoded Zicsr instructions and
rejects an attempted write to an address marked read-only by bits 11:10. The
check does not establish that the CSR exists, that its extension is enabled,
or that virtualization/debug policy will not intercept the access; it does not
deliver an exception or perform the CSR operation. The address convention is
specified in the [RISC-V Privileged Architecture CSR mapping](https://docs.riscv.org/reference/isa/priv/priv-csrs.html).
