# First-class vector types implementation plan

**Goal:** Carry homogeneous vector types from the lifted IR into persistent types and ABI recovery.

**Architecture:** Extend the immutable types model, codec and ABI layout, then add shape conversion to decompiler type recovery. Preserve prior serialized kind values by appending the new kind and introduce codec version 5.

## Tasks

1. Add vector model, formatting, validation, layout, and v5 serialization with legacy decode fixtures.
2. Recover vectors from explicit prototypes, vector result facts, ABI vector arguments, and ABI vector return registers.
3. Document the supported subset and codec compatibility boundary.
4. Build the type and decompiler recovery targets and run their focused CTests.
