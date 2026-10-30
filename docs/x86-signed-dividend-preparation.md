# x86 signed-dividend preparation

`evaluate_x86_sign_extend_accumulator_instruction` evaluates the implicit
register forms `CBW`, `CWDE`, `CDQE`, `CWD`, `CDQ`, and `CQO`. The first three
sign-extend AL/AX/EAX into AX/EAX/RAX. The latter three fill DX/EDX/RDX with
all zeroes or all ones according to the sign bit of AX/EAX/RAX. The result
indicates which implicit register is written; no status flags change.

The helper checks decoded implicit register read/write facts and width mode.
The caller supplies the accumulator bit pattern and commits the returned
register outputs. It does not perform division or report divide exceptions.
