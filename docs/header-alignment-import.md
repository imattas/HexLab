# Header alignment import

The bounded C/C++ header importer accepts standard `alignas(n)` and C11
`_Alignas(n)` declarations when the argument is an integer literal from zero
through 4096. Zero has no effect; nonzero values must be powers of two. GNU
`__attribute__((aligned(n)))` and Microsoft `__declspec(align(n))` use the
same bound. Integer literals may be decimal or hexadecimal and carry `U`/`L`
suffixes.

Alignment specifiers are supported on aggregate definitions, named aggregate
members, typedef declarations, and object declarations. Aligned typedefs
propagate their alignment into later aliases, pointers, arrays of the typedef,
and aggregate member layout. Object and typedef alignment is represented in
the existing type record; member-only alignment is preserved as the member's
effective alignment. Aggregate tail padding and alignment follow that metadata.
Existing ABI layout and argument classifiers consume these type alignments,
subject to their ABI alignment limits.

Over-aligned array objects retain declaration-level alignment in the imported
`HeaderSymbol`; this does not change array element stride. Over-aligned array
typedefs are rejected because the current type record cannot express that
alignment independently of element stride.
Alignment expressions beyond integer literals (including `alignof`, symbolic
constants not preprocessed into literals, and arithmetic expressions),
alignment of function declarations, and compiler-specific alignment
attributes with unmodeled semantics remain unsupported and fail explicitly.
Values above 4096 and non-power-of-two nonzero values are malformed.
