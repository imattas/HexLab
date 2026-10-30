# Compound template-argument pack expansion

The bounded header importer can expand a compound template argument containing
one already bound type, integral, or template-name parameter pack. It substitutes
each pack element into the pattern and parses the result using the existing
declaration and constant-expression parsers. It does not manufacture a new type
kind or invoke a compiler.

```cpp
template <typename First, typename Second>
struct Pair { First first; Second second; };

template <typename T>
struct Box { T value; };

template <typename... Types>
using PointerPair = Pair<const Types*...>;
using Pointers = PointerPair<int, short>;

template <typename... Types>
using BoxPair = Pair<Box<Types>...>;
using Boxes = BoxPair<int, short>;

template <typename... Types>
using ArrayPair = Pair<Types[2]...>;
using Arrays = ArrayPair<int, short>;

template <typename... Types>
using CallbackPair = Pair<void (*)(Types)...>;
using Callbacks = CallbackPair<int, short>;
```

`Pointers` contains pointers to const `int` and const `short`; it does not
qualify the pointers themselves. `Boxes` contains separately instantiated
`Box<int>` and `Box<short>` types. `Arrays` contains two fixed arrays with two
elements each. `Callbacks` contains two function pointers, each taking its
corresponding element type. Existing target scalar/pointer widths, packing,
alignment, array limits, and function-signature rules determine their concrete
type graphs and layouts. The same mechanism accepts a repeated occurrence of
the pack, for example a nested `Pair<Types, Types>...`; both occurrences use
the same current element.

Integral packs can produce integer arguments or supply fixed array extents in
type arguments:

```cpp
template <unsigned First, unsigned Second>
struct Blocks {
    unsigned char first[First];
    unsigned char second[Second];
};

template <unsigned... Counts>
using IncrementedBlocks = Blocks<(Counts + 1)...>;
using Payload = IncrementedBlocks<2, 4>;

template <unsigned... Counts>
using ByteArrayPair = Pair<unsigned char[Counts]...>;
using Buffers = ByteArrayPair<2, 4>;
```

`Payload` retains array lengths three and five. `Buffers` retains lengths two
and four. Arithmetic uses the existing bounded signed constant-expression
subset: a final negative value, overflow, division by zero, or unknown name
fails. Every expanded integer is also checked against the destination
parameter's declared width. Operators containing `<` or `>` must remain
parenthesized in integer template arguments. This does not add arbitrary
constant evaluation, unsigned expression arithmetic, or fold expressions.

Template-name packs can instantiate each bound template inside a type pattern:

```cpp
template <typename T>
struct Handle { T* value; };

template <template <typename> class... Containers>
using ContainerPair = Pair<Containers<int>...>;
using Wrapped = ContainerPair<Box, Handle>;
```

`Wrapped` contains `Box<int>` and `Handle<int>`. Bound template names still
must pass the existing exact template-template parameter-shape checks. Direct
`Containers...` forwarding remains supported when the destination expects
template names; an instantiated type cannot fill a template-name parameter.

Expansion preserves source pack order. It can fill fixed destination
parameters, a trailing destination pack, or both. An empty pack contributes
zero arguments and leaves destination defaults to their normal processing.
Too few or too many resulting arguments and argument-kind mismatches are
errors. Each completed argument list, including arguments before and after
an expansion, remains capped at 32. Pattern delimiters, nested template parsing,
and substitution obey the configured parser nesting bound. Source, expanded
input, tokens, and fixed array extents retain their existing limits. A compound
pattern is instantiated only when its enclosing declaration is referenced;
an empty pack does not parse hypothetical element types.

Each pattern must reference exactly one distinct bound pack. Repeated use of
that same pack is supported; zipping two different packs, nested ellipses in
one pattern, base/member declaration expansions, function/method parameter
pack expansions, specialization pack deduction, and general C++ template
deduction remain unsupported. Reference declarators and other type syntax
outside the ordinary importer subset do not become supported merely by
appearing in an expansion. This feature keeps the overall C/C++ importer
partial.
