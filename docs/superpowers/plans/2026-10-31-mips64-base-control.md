# MIPS64 base control completion

The existing decoder already covers the common classic integer ALU, HI/LO,
shift, bitfield, branch, and scalar memory families. Complete the coherent
exception, cache/order, and hardware-control gap without changing MIPS32.

1. Append stable opcode IDs for CACHE, SYNCI, RDHWR, DI/EI and the exact
   SSNOP/EHB/PAUSE idioms. Reuse existing SYSCALL/BREAK/SYNC IDs.
2. Decode fixed fields, unsigned selectors, full exception codes, and signed
   64-bit effective addresses. Record GPR/Status effects and terminal traps;
   retain existing delay-slot ownership and conservative rejection of traps
   in delay slots.
3. Format the new forms and lift them into explicit named effects. Address
   hints must consume effective addresses rather than load values. DI/EI
   preserve the old Status value and update IE in parallel; hardware results
   remain opaque. Record unconditional exception edges.
4. Invalidate cached function analysis, document boundaries, and extend only
   MIPS64 capability evidence, retaining partial status.
5. Run compile and static checks only. No tests are added or run, as required
   by the delegated repository instructions. Commit the isolated branch.

Validation: all three Debug targets linked successfully with
`BUILD_TESTING=OFF`; `git diff --check` and capability CSV structure checks
passed. A separate static review reported no critical or important findings.
