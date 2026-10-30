# x86 LOOP-family lifting

The native x86/x86-64 decompiler now gives `LOOP`, `LOOPE`/`LOOPZ`,
`LOOPNE`/`LOOPNZ`, and `JCXZ`/`JECXZ`/`JRCXZ` explicit branch predicates.
For LOOP variants it decrements CX, ECX, or RCX according to the decoded
address size, then branches when the resulting counter is nonzero. LOOPE also
requires the incoming ZF to be set; LOOPNE requires it to be clear. The JCXZ
family tests the selected counter for zero without changing it. None of these
instructions changes flags.

The counter update is emitted before the branch so SSA and the branch
predicate use the same post-decrement value. The decoder-provided CFG targets
remain authoritative for taken and fallthrough edges. `67` address-size
overrides select the 16- or 32-bit counter forms where supported; in long mode
the default counter is RCX and a 32-bit override selects ECX. Malformed
synthetic instruction facts that disagree with the decoded register effects
remain on the generic branch path.

This models one instruction's counter and branch effects. It does not execute
the surrounding loop or infer runtime counter values.

The derived-cache engine version is 77 because decoded LOOP-family facts now
retain the full-register effects of address-size counter writes. The same
version also invalidates cached facts for the DEX register-index codec
widening in this repository wave.
