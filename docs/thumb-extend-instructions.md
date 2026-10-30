# Thumb extend-register instructions

The Thumb-1 decoder recognizes the four 16-bit extend-register encodings in
the `0xB2xx` group: `SXTH`, `SXTB`, `UXTH`, and `UXTB`. Bits 2:0 select
the destination and bits 5:3 select the source low register.

The Thumb-2 decoder also recognizes the scalar register-extend class:

| First halfword | Rn != 15 | Rn = 15 alias |
| --- | --- | --- |
| `FA0n` | `SXTAH` | `SXTH.W` |
| `FA1n` | `UXTAH` | `UXTH.W` |
| `FA4n` | `SXTAB` | `SXTB.W` |
| `FA5n` | `UXTAB` | `UXTB.W` |

The second halfword has fixed high bits `1111`, destination bits 11:8,
fixed bits 7:6 = `10`, rotation bits 5:4, and source bits 3:0. Rotation
selects ROR by 0, 8, 16, or 24 before extracting the low byte or halfword.
The Rn=15 alias has no PC read. The bounded decoder rejects SP/PC source or
destination and SP as the accumulator, following ARMv7 Thumb restrictions;
ARMv8 SP relaxations need an explicit architecture profile. The packed-byte
`SXTB16/UXTB16/SXTAB16/UXTAB16` family is also decoded for A32 and Thumb-2.
Other FAxx DSP classes remain unsupported.

All decoded forms carry 32-bit destination writes, source reads, and matching
access facts. Extend-add forms read the accumulator separately, preserving
aliasing with either source. These instructions preserve APSR, including
outside IT blocks. The decoder retains its incoming IT predicate and advances
ITSTATE once for the complete four-byte instruction. Unknown IT state stays
unknown. Formatting uses the existing architectural mnemonic and rotated
register operand representation; encoded instruction length distinguishes
wide aliases from narrow forms.

The shared ARM decompiler now lowers A32 and Thumb scalar byte/halfword
extensions and the packed-byte extension family.
Rotation is retained before extraction. Unsigned forms mask the low 8/16 bits;
signed forms use a typed 32-bit left/arithmetic-right shift pair to sign-extend
them. Extend-add then adds the accumulator with 32-bit wrapping semantics.
This correctly preserves the high-to-low wrap in halfword ROR #24. Existing
SSA and integer constant propagation consume the resulting expressions.
Packed-byte forms independently extend the selected low and high bytes,
perform optional per-halfword wrapping additions, and reassemble the two
16-bit result lanes. This is bitwise behavior; it does not model DSP
architecture feature availability or saturation flags.
Known A32/IT predicates select the previous destination when false, and
unknown IT context retains the existing opaque effect. No APSR definition,
memory effect, or control transfer is introduced.

Encoding and operation shapes follow LLVM's primary
[Thumb-2 extend definitions](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/ARM/ARMInstrThumb2.td)
and the Arm [instruction specification](https://community.arm.com/cfs-file/__key/communityserver-discussions-components-files/471/DDI0553B_5F00_y_5F00_armv8m_5F00_arm.pdf).
The decoder does not perform target CPU/DSP feature checks; profile-based
availability and Armv8 register relaxations remain outside this slice.
