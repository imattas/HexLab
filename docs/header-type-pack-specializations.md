# Type-pack partial specializations

The bounded header importer now matches a partial specialization when the
primary class template consists of one trailing type pack and the specialization
expands one type pack over pointer elements:

```cpp
template<class... Args>
struct PointerList { unsigned char fallback; };

template<class... Pointees>
struct PointerList<Pointees*...> {
    Pointees* values[sizeof...(Pointees)];
};

template<class... Pointees>
struct PointerList<const Pointees*...> {
    const Pointees* values[sizeof...(Pointees)];
};

using MixedPointers = PointerList<int*, unsigned char*>;
using ConstPointers = PointerList<const int*, const long*>;
```

The specialization checks every supplied primary argument against the same
element pattern, deduces the pointee pack, and substitutes it into the selected
body. `T*...` and `const T*...` retain their relative specificity, so the
const-pointee form wins over the unqualified pointer form when both can match.
An empty argument pack matches the expansion as an empty deduced pack. The
selected body must still be valid for that empty pack; for example, a zero
array extent remains unsupported.

This does not implement general partial-specialization ordering or arbitrary
pack-pattern deduction. The primary must have exactly one type pack. A
specialization must declare exactly one type pack and use a single `T*...` or
`const T*...` pattern. Fixed parameters before a pack, compound patterns such
as `Pair<T, U>*...`, non-type or template-template packs, and explicit full
specializations of a primary pack remain unsupported. Other specializations
continue to use the existing bounded non-pack matcher.
