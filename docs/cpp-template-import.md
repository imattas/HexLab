# C++ template declarations in header import

Header import retains template declaration metadata in `HeaderImportResult::templates`.
Each record gives the qualified name, declaration kind, function signature when the
record is a function template, and ordered parameters. Parameters preserve whether
they are type, integral non-type, or template-template parameters, their nested
template-template parameter shape, defaults that the importer retains, and whether
the parameter is a pack.

Class, struct, union, and alias templates accept type parameters, integral non-type
parameters, template-template parameters, defaults, and a trailing pack. The
importer can instantiate these declarations from concrete type, non-negative
integer, and template-name arguments. Integral arguments are checked against
their declared width. A non-type parameter can drive a member array extent. A
template-template parameter can instantiate a previously declared class or
alias template inside an aggregate body or alias target. It can also be forwarded
as a template-name argument. Concrete aggregate instance names include every
expanded pack argument, so different packs produce distinct modeled types.

An argument consisting of a bound pack name followed by `...` expands that pack
into the destination template's argument list. Type, integral, and template-name
packs all use this rule, and each expanded argument is checked against its
destination parameter. A pack can fill fixed parameters as well as a trailing
pack. Empty packs contribute no arguments; `<>` also applies alias defaults.

```cpp
template <typename First, typename Second>
struct Pair {
    First first;
    Second second;
};

template <typename... Types>
using PairFrom = Pair<Types...>;

using IntegerPair = PairFrom<unsigned int, unsigned short>;

template <typename T>
struct Box { T value; };

template <template <typename> class Container = Box, typename T = unsigned int>
using Apply = Container<T>;

using DefaultBox = Apply<>;

template <unsigned First, unsigned Second>
struct Blocks {
    unsigned char first[First];
    unsigned char second[Second];
};

template <unsigned... Counts>
using BlocksFrom = Blocks<Counts...>;

using Payload = BlocksFrom<2, 4>;

template <typename... Types>
struct Marker { unsigned char tag; };

template <typename... Types>
using MarkerFrom = Marker<Types...>;

using EmptyMarker = MarkerFrom<>;

template <template <typename> class... Containers>
struct Catalog { unsigned char tag; };

template <template <typename> class... Containers>
using CatalogFrom = Catalog<Containers...>;

using BoxCatalog = CatalogFrom<Box>;

template <typename... Types>
struct PackSized {
    unsigned char storage[sizeof...(Types) + 1];
};

using EmptyPackSized = PackSized<>;
using ThreePackSized = PackSized<int, short, char>;
```

`IntegerPair` uses the existing target scalar widths, alignments, and ordinary
aggregate member placement. `DefaultBox` is `Box<unsigned int>`, `Payload` has
two byte arrays of lengths two and four, and `EmptyMarker` has a single byte
member. `BoxCatalog` forwards a template-name pack into `Catalog<Box>` and
retains only the declared byte member. Expansion creates no implicit members
or additional layout rules.

`sizeof...(Types)` is available in the bounded integer-expression contexts
already supported by the importer, including array extents and integer
non-type template arguments. `EmptyPackSized` therefore has a one-byte array and
`ThreePackSized` has a four-byte array. The expression requires a bound pack
from the current template instantiation; it does not evaluate arbitrary
`sizeof` expressions over C++ types.

Concrete aggregate instances can contain member typedefs, ordinary type aliases,
and uninitialized static data declarations. Their aliases export qualified keys
such as `Box<unsigned short>::value_type`; a known aggregate type argument can
qualify a member alias in `typename Container::value_type`. Static data remains
outside instance layout. See [C++ member declaration import](header-cpp-member-import.md).
Member alias templates and inherited using-declarations remain unsupported.


Function-template prototypes with type parameters are retained as function types
whose parameter and result types use symbolic named references. Function bodies,
explicit function-template specializations, function-template non-type/template-
template parameters, and overloaded function-template metadata are unsupported.

Pack expansion supports direct `Pack...` forwarding and compound
template-argument patterns over one bound pack, including `Types*...`,
`Box<Types>...`, abstract array/callback types, integral expressions, and
template-name packs instantiated as `Containers<int>...`. A repeated occurrence
of the same pack in a pattern uses the same element for that expansion.
Empty packs contribute no arguments. See
[compound pack expansion](header-compound-pack-expansions.md) for examples,
destination validation, and limits. Multiple distinct packs in one pattern,
nested ellipses inside a pattern, member declarations, method parameter
expansions, and base packs remain unsupported. Fold expressions and
general `sizeof` expressions remain unsupported; only `sizeof...(Pack)` is
recognized as a bounded integer expression.
A trailing pack can be declared without using it in the body. Explicit and
partial class-template specializations support the documented direct type,
pointer, and integral patterns, but still reject template-template parameters
and packs. Template-template argument matching is deliberately strict: the
nested parameter count, kinds, integral parameter types, and pack markers must
match exactly, including for every element of a template-template pack.
Each expanded argument list and parameter list is capped at 32. Recursive
template-template parameter lists, alias expansion, and aggregate instantiation
also obey the configured nesting limit. The parser retains its token and array
limits; unsupported forms return a diagnostic instead of a guessed layout.
