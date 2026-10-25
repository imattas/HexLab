# Anonymous namespaces in C++ header import

The bounded C++ header importer accepts `namespace { ... }` blocks. All
unnamed namespace blocks at the same enclosing namespace scope within one
`import_c_header` call share one synthetic namespace, matching the rule that
they name the same unnamed namespace in a translation unit. Nested unnamed
namespaces use their own synthetic namespace at the nested scope.

Declarations are retained under deterministic internal names such as
`@anonymous_0::InternalType` or
`graphics::@anonymous_1::InternalType`. The `@` component cannot be written as
a C++ identifier, so source declarations cannot collide with these names. A
later declaration in the enclosing namespace can refer to an anonymous
namespace type by its unqualified name; the importer models the implicit
using-directive inserted by C++ after the unnamed namespace definition.
Declarations inside the unnamed namespace can also use names from enclosing
namespaces.

The generated scope numbers are stable for the same declaration order in a
single import. They identify imported declarations; they do not claim to
preserve compiler-specific mangling or provide a cross-translation-unit
identity. Separate imports do not merge anonymous namespaces. Symbol export
uses the synthetic qualified name because the shared type model has no
translation-unit-local linkage field. General C++ overload resolution,
argument-dependent lookup, and complete namespace hiding rules remain outside
the importer's supported subset.
