# Integral non-type alias templates

The bounded header importer can instantiate C++ type aliases with integral
non-type parameters. The parameter type must be an integer type no wider than
64 bits. Arguments and defaults use a bounded integer constant-expression
subset, then are checked against the declared parameter width. It supports
integer literals, earlier bound parameters, parentheses, unary `+`, `-`, `~`,
arithmetic `+`, `-`, `*`, `/`, `%`, and bitwise `&`, `^`, `|`.

```cpp
template <typename T, size_t N>
using FixedArray = T[N];

using Header = FixedArray<uint32_t, 2 + 2>;
```

`Header` is imported as a four-element array of 32-bit unsigned integers.
Array extents can also use the bound values and the same expression subset:

```cpp
template <size_t N, size_t Count = N + 1>
using DoubledBytes = unsigned char[N * 2 + 1];

using SevenBytes = DoubledBytes<3>;
```

`SevenBytes` has seven elements, and the default `Count` is evaluated using
the earlier `N` binding. Nested alias instantiations may forward an in-scope
integral parameter:

```cpp
template <size_t N>
using Bytes = unsigned char[N];

template <size_t N>
using Packet = Bytes<N>;
```

Type parameters can retain defaults, and integer parameters can use literal
defaults. Template argument count remains capped at 32. A zero value is valid
as a template argument, but cannot be used as a fixed array extent.

Alias templates also support template-template parameters and trailing type,
integral, or template-name packs. Direct `Pack...` arguments forward every bound
element into a nested class or alias template, including empty packs. Expanded
arguments retain their kinds and are checked against the destination parameter
types; integer range checks apply there too. `<>` can use an alias's defaults
or bind an empty pack. See [C++ template declarations](cpp-template-import.md)
for forwarding examples and the strict template-template matching rules.

The importer deliberately rejects negative final values, enumerator names,
pointer/reference/member-pointer non-type parameters, shift/comparison/logical
operators, and compound pack expansion patterns such as `Values + 1...`.
Expressions are capped at 4096 tokens/operations and the configured parser
nesting limit; overflow, division by zero and unbound names fail explicitly.
Integral
non-type parameters are also supported on class/struct/union templates; their
specialization subset is documented in
[integral non-type class-template specializations](header-non-type-specializations.md).
No host compiler or filesystem lookup is used to resolve template expressions.
