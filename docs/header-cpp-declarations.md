# Imported namespace declarations and callbacks

The bounded header importer supports named, nested C++ namespace blocks,
including C++17 `namespace outer::inner { ... }` spelling. It qualifies
namespace-scope aggregate tags, enums, typedefs, objects, and function symbols
in `HeaderImportResult::symbols`. Types declared in a namespace can be
referenced by unqualified name within that namespace or by a qualified name
such as `outer::inner::Record` elsewhere. Struct/union injected names and
enum type names are available to type lookup within their namespace.

Unscoped enum constants are recorded under their enclosing namespace, for
example `outer::inner::Ready`. `enum class` and `enum struct` are also
represented; their constants are recorded under the enum's qualified name,
such as `outer::inner::State::Ready`. Scoped enums use the default `int`
underlying type. Explicit enum underlying types are rejected because the type
record does not preserve scoped-enum and explicit-underlying metadata.

The C declarator grammar supports nested function pointers in aggregate
members and function parameters, including function pointers inside function
pointer signatures, arrays of function pointers, and functions returning
pointers to arrays of function pointers where the immutable type graph can
represent them. Calling-convention metadata remains attached to the function
type layer represented by the parsed declarator.

Class, struct, and union bodies accept ordinary method prototypes. They retain
each method's function signature, declaration order, and current
public/protected/private access label. Class bodies default methods to private;
struct/union bodies default methods to public. `static` methods are retained as static;
non-static methods record a pointer to the declaring aggregate as `this_type`.
Methods do not affect object layout, and aggregates with methods but no data
members retain the C++ empty-object size of one byte. Overloaded names are
retained as separate method records. A data member and method cannot share a
name in the imported model.

Function-template non-type/template-template parameters and packs,
specialization patterns outside the documented subset, compound pack expansions,
function and enumerator using-declarations, method bodies,
constructors/destructors, virtual and pure-virtual methods, cv/ref-qualified
methods, static data initializers/inline definitions, and explicit enum underlying types remain
unsupported and fail with an importer error. Bounded class/struct/union and alias
templates are supported as documented in `header-import.md`. Namespace names are case-sensitive. The importer
does not model C++ lookup rules beyond enclosing namespace scopes, qualified
type names, type using-declarations, and the documented `using namespace`
lookup.

Class-scoped typedefs, `using Name = Type` aliases, and static data declarations
are supported for ordinary aggregates and concrete class-template instances.
Aliases export `Owner::Alias` keys and retain the exact target type. Static data
retains type, access and source declaration order in the aggregate's
`static_data_members()` vector and exports qualified object symbols, without
changing instance fields or layout. See [C++ member declaration import](header-cpp-member-import.md)
for qualification, incomplete declarations, examples and explicit limits.
