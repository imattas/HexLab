# A64 scalar bit and byte reversal

The A64 integer decoder recognizes the scalar `RBIT`, `REV16`, `REV32`, and
`REV` register forms for 32-bit `W` and 64-bit `X` registers where the
architecture defines them. `REV Wd, Wn` shares the REV32 encoding family but
reverses the bytes of the complete 32-bit word; `REV32 Xd, Xn` reverses bytes
independently in each 32-bit lane. `REV Xd, Xn` reverses all eight bytes.
`REV16` swaps the two bytes in each 16-bit lane, and `RBIT` reverses bit order
over the full operand width. These are pure GPR operations and do not write
NZCV. Writes to `WZR`/`XZR` are discarded by lifting as for other A64
zero-register destinations.

The decompiler emits bitvector expressions: `RBIT` uses staged power-of-two bit
swaps, while the REV forms assemble each output byte from its corresponding
input lane. The 32-bit forms operate on 32-bit values, so normal A64 W-register
zero-extension applies. Reserved 32-bit encodings in the REV operation group
remain unsupported.

Reference: [Arm A-profile A64 Instruction Set Architecture, base instructions](https://support.arm.com/documentation/ddi0602/2025-12/Base-Instructions/RBIT--Reverse-bits-).
