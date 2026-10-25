# C++ member declaration import

The bounded header importer accepts ordinary named `class` declarations, member typedefs, `using Name = Type` aliases, and static data-member declarations in classes, structs and named unions. It uses the existing immutable type graph and existing static-data serialization; it does not add inheritance, vtables, constructors, or storage definitions.

```cpp
namespace api {
class Catalog {
public:
    using Word = unsigned short;
    typedef Word (*Callback)(Word);
    static Catalog singleton;
    static Word totals[];
    static Callback callback;
    Word current;
    Word read();
};
}

using Count = api::Catalog::Word;
using CatalogType = api::Catalog;
using SameCount = CatalogType::Word;

template <typename T>
struct Box {
    using value_type = T;
    static T shared;
    T value;
};

using Words = Box<unsigned short>;
using Element = Box<unsigned short>::value_type;
template <typename Container>
using ElementOf = typename Container::value_type;
using Again = ElementOf<Words>;
```

`Catalog::current` is the only instance data member in this example. With the default two-byte `short` model, `Catalog` has size and alignment two. Its static declarations and method add no object subobjects or alignment. An otherwise empty C++ class, or an aggregate containing only aliases, methods or static data, uses the existing one-byte empty-object representation, subject to supported explicit aggregate alignment. Plain empty C aggregates remain outside the supported subset.

Member aliases appear in `HeaderImportResult::symbols` as `typedef_name` entries under fully qualified keys such as `api::Catalog::Word`. They point at the exact target type and become available to later declarations in the same body. They do not become enclosing namespace aliases. Namespace lookup resumes when the aggregate closes. Known aggregate typedefs and bound template type parameters can qualify aliases through the underlying aggregate identity; concrete template instances also accept a `::member_type` suffix. Lookup is bounded and rejects distinct matching identities rather than choosing by declaration order. Symbolic dependent members that have no concrete aggregate definition remain unsupported.

Static data appears in `Type::static_data_members()` with name, type, current public/protected/private access, and a zero-based source declaration ordinal. Methods and static data use the same ordinal sequence; instance fields and aliases occupy positions too, so retained ordinal values can have gaps. `class` defaults to private access; struct/union defaults to public. Each static declaration also appears as a qualified `object` symbol, for example `api::Catalog::singleton`. These are declaration records: they do not claim that a definition, address, initialization, or lifetime has been recovered.

A non-inline static declaration can retain an incomplete aggregate type or incomplete array. The importer does not lay out that storage. In the example, `singleton` keeps a symbolic reference to the declaring class and `totals` keeps an incomplete array, while the containing instance remains complete. Static declarations are excluded from members, offset/size/alignment accumulation and bitfield-unit advancement. These declaration semantics follow [the C++ static data-member rules](https://eel.is/c++draft/class.static.data).

New aliases and static declarations are checked for collisions with existing aliases, instance members, static data and methods in the imported aggregate. Typedefs of function types are aliases rather than method declarations, and callback pointers keep their complete nested signature. Existing target scalar widths, packing, field alignment and bitfield rules still determine every instance field. Class names and bodies with C++ member declarations are injected into ordinary type lookup; plain C tags retain their separate historical lookup behavior.

The importer rejects in-class initializers, inline static variable definitions, static bitfields, void static objects, and declaration-specific static alignment/packing attributes that `StaticDataMember` cannot preserve. A previously declared aligned type remains usable. `constexpr`, `constinit`, thread-local data, member alias templates, inherited using-declarations, new nested aggregate/enum declarations, constructors/destructors, inheritance, virtual methods and unrepresented cv/ref/noexcept function qualifiers remain unsupported. Alias access labels are not represented or enforced, just as instance data-member access is not retained by the shared type model. Class lookup is declaration-ordered and bounded; this is not a complete C++ name-lookup or access checker. No system compiler is invoked.
