# JVM narrow array loads

`evaluate_jvm_narrow_array_load_instruction` extends a loaded `baload`,
`caload`, or `saload` element to the JVM i32 stack representation. `baload`
sign-extends byte-array elements, but zero-extends boolean-array elements;
the caller supplies that array-kind distinction. `caload` zero-extends its
16-bit character value, and `saload` sign-extends its 16-bit short value.

The adapter validates the decoded JVM opcode and operand-free one-byte shape.
It consumes already-read memory bits, so null checks, bounds checks, array
storage, and stack updates remain caller-owned.
