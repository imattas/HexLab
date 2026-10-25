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
```

`IntegerPair` uses the existing target scalar widths, alignments, and ordinary
aggregate member placement. `DefaultBox` is `Box<unsigned int>`, `Payload` has
two byte arrays of lengths two and four, and `EmptyMarker` has a single byte
member. `BoxCatalog` forwards a template-name pack into `Catalog<Box>` and
retains only the declared byte member. Expansion creates no implicit members
or additional layout rules.

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

Expansion is limited to direct `Pack...` template arguments. Compound patterns
such as `Types*...` or `Box<Types>...`, member declarations, method parameter
expansions, base packs, `sizeof...`, and fold expressions remain unsupported.
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
