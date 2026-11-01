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

Template-template arguments can also be matched by a direct template-template
parameter name or by a fixed previously declared class or alias template name.
The parameter shapes of template-template arguments must match the relevant
template-template parameter exactly. Fixed template names use normal qualified-
name, using-directive, and inline-namespace resolution. Compound template
argument patterns and template-template parameter packs remain unsupported.

Bounded dependent arithmetic patterns can deduce one otherwise-unbound
non-type parameter when it occurs once in the expression and the inverse is
unique. The primary and specialization parameters must use signed 64-bit
integer types, and unsigned-suffixed literals are rejected so modular arithmetic
is not mistaken for signed arithmetic. Addition, subtraction, and exact multiplication
by a nonzero constant are supported, including nested parentheses; the inferred
value is range checked against its declared integral parameter type and then
evaluated again to verify the match. For example, `Buffer<T, N + 1>` can select
a specialization and bind `N` from the concrete extent. Expressions with
multiple unknowns, repeated occurrences, division, bitwise operators,
zero-multiplier ambiguity, and values outside the signed expression range
remain unsupported. Enumerator
expressions, negative values, and pointer or reference non-type arguments also
remain unsupported. Type patterns are limited to
the existing direct `T`, `T*`, `const T*`, and fixed-type forms. Template-
template parameters and parameter packs can appear in primary class templates,
but parameter packs remain unsupported by specializations. Scope is
part of template identity, so same-named templates in distinct namespaces
remain independent. Function
and alias-template specializations remain unsupported. Partial candidates are
compared per primary argument. A candidate wins only when its pattern is at
least as strong on every argument and stronger on at least one; incomparable
or equivalent matches fail as ambiguous rather than depending on declaration
order. Template argument and parameter counts remain capped at 32, and
recursive instantiation remains bounded by the configured nesting limit.
