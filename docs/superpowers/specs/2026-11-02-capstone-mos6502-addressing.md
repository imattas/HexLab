# MOS6502 fallback addressing facts

Scope: complete a bounded family of documented NMOS addressing facts in the opaque Capstone fallback, without changing the native decoder or adding lifting semantics.

The bundled MOS65XX backend does not install a `reg_access` callback. Consequently `cs_regs_access` fails and the fallback drops explicit accumulator shift operands and all index-register dependencies. Preserve the accumulator operand for the exact one-byte ASL/ROL/LSR/ROR encodings 0A/2A/4A/6A, checked against instruction ID, accumulator mode, and register identity. Its width is eight and access is read-write. Unknown register forms retain existing conservative behavior.

Read the X/Y registers present in typed memory address expressions after the generic register-access handling, so later replacement cannot erase them. This covers zero-page X/Y, absolute X/Y, indexed-indirect and indirect-indexed addressing.

Memory transfer width is eight only for proven data-access IDs. Address-only target operands have no data width. The exact three-byte 6C JMP indirect encoding reads a 16-bit pointer at its encoded address, but retains no direct target. Do not model NMOS page wrapping as an executable address expression or resolve pointer contents.

Constraints: no tests added or run; no CI, push, native 6502 semantics changes, capabilities.csv edits, or artifact cleanup. Build Windows and WSL hexlab_processors and hexlab_cli locally with BUILD_TESTING=OFF. Preserve original bytes, display, Opcode::opaque, existing direct-flow facts, and conservative unknown roles.

Evidence: third_party/capstone/arch/MOS65XX/{m6502.inc,MOS65XXModule.c,MOS65XXDisassembler.c}; cs.c:cs_regs_access; docs/capstone-semantic-fallback.md. These vendored sources establish encoding and detail contracts without relying on mutable external documentation.
