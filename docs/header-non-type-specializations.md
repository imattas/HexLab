# Integral non-type class-template specializations

The bounded C++ header importer can match explicit and partial class-template
specializations whose primary template uses integral non-type parameters. A
specialization argument may be a non-negative integer literal or a direct
integral parameter name:

```cpp
template <typename T, unsigned N>
struct Buffer {
    T value;
    unsigned char storage[N];
};

template <typename T>
struct Buffer<T, 0> {
    T value;
};

template <unsigned N>
struct Buffer<unsigned char, N> {
    unsigned char storage[N];
};

template <>
struct Buffer<unsigned int, 4> {
    unsigned int words[4];
};

using EmptyBuffer = Buffer<unsigned int, 0>;
using ByteBuffer = Buffer<unsigned char, 8>;
using WordBuffer = Buffer<unsigned int, 4>;
```

`EmptyBuffer` selects the `T, 0` partial specialization, `ByteBuffer` selects
the `unsigned char, N` partial specialization, and `WordBuffer` selects the
exact explicit specialization. Layout is computed from the selected body when
the concrete type is referenced. Primary arguments and specialization
parameters are range-checked against their declared integer widths.

When a specialization has both type and integral parameters, direct type
deduction and exact integer matches can be combined. Integral literals accept
decimal, octal, and hexadecimal spellings with U/L suffixes across the full
unsigned 64-bit range; equivalent spellings are canonicalized when detecting
duplicate declarations. Repeated direct integral parameter names must match
the same value. A specialization parameter that cannot be deduced from its
pattern is rejected.

The importer does not evaluate arithmetic or symbolic expressions in
specialization patterns: `N + 1`, enumerators, negative values, and pointer or
reference non-type arguments remain unsupported. Type patterns are limited to
the existing direct `T`, `T*`, `const T*`, and fixed-type forms. Template-
template parameters and parameter packs can appear in primary class templates,
but specializations of templates that use either are not supported. Scope is
part of template identity, so same-named templates in distinct namespaces
remain independent. Function
and alias-template specializations remain unsupported. Ambiguous matches fail
instead of depending on declaration order. Template argument and parameter
counts remain capped at 32, and recursive instantiation remains bounded by the
configured nesting limit.
