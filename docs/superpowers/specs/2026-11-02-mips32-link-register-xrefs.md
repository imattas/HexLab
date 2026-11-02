# MIPS32 delayed link-register reference design

## Goal

Propagate architectural link values through classic MIPS32 call delay slots so an instruction in that slot can use the return-address register as a proven code address.

## Behavior

- Recognize `JAL`, `JALR`, `BLTZAL`, `BGEZAL`, `BLTZALL`, and `BGEZALL` only in MIPS32 mode. Conditional REGIMM link instructions produce a fact only when the source register proves the branch is taken.
- Derive the link as the call instruction address plus eight bytes. `JAL` and REGIMM link forms must write GPR 31; `JALR` must have exactly one decoded nonzero GPR destination.
- Retain the value only when the address fits a 32-bit image space and points to four initialized bytes in an executable segment.
- Apply the link after the call transfer so its delay-slot instruction observes the value. Clear it on the recovered call continuation using existing CFG behavior.
- Preserve the link fact if relocation handling makes the call target opaque; the relocation does not change the architectural PC+8 link.
- Do not resolve indirect call targets or invent links for false/unknown REGIMM conditions, malformed register effects, uninitialized code, non-MIPS32 modes, or unsupported compact-control encodings.

## Scope

Modify the MIPS reference helper, MIPS register-state propagation and function-analysis fingerprint. Document the semantics in `docs/architecture-xrefs.md`. No decoder changes are required because the MIPS32 decoder already exposes the link destination and classic delay slot.

## Verification

Build `hexlab_analysis` on Windows and WSL with tests disabled. Runtime/test execution is not part of this change.
