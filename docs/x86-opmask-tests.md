# AVX-512 opmask test instructions

The VEX.128.0F.W0 KTEST/KORTEST forms accept K-register operands and derive B/W/D/Q width from the mandatory prefix and W bit. Implemented encodings are 98 /r (KORTEST) and 99 /r (KTEST), with VEX.L=0 and reserved VEX.vvvv. EVEX encodings, memory operands, and extended K registers are rejected.

The first ModRM operand is DEST and the second is SRC. KTEST sets ZF when DEST AND SRC is zero and CF when DEST AND NOT SRC is zero. KORTEST sets ZF when DEST OR SRC is zero and CF when DEST OR SRC is all ones. Both clear OF, SF, AF, and PF. The evaluator returns a RFLAGS bit-vector and a written-bit mask so callers can preserve bits outside the architectural write set.

No dedicated decompiler expression is emitted; generic flag-register access facts are available, and condition consumers remain supported through existing FLAGS analysis. The evaluator describes arithmetic flag bits only; reserved and system RFLAGS bits are preserved by the caller.

Reference: Intel 64 and IA-32 Architectures SDM, Volume 2A, KTEST/KORTEST entries, https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf
