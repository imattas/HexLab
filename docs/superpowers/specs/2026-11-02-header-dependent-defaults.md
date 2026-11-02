# Header dependent default binding

Extend the existing bounded C/C++ header importer so alias and aggregate
template defaults evaluate using all preceding concrete type, integral and
template-template arguments. This closes a `types.headers` argument-binding
gap without changing public result/type interfaces.

## Approach

Use the existing nested `Parser` context for declaration-ordered defaults;
extend `IntegerExpressionParser` rather than introduce another evaluator.
Eager textual substitution would lose type identity and source bounds. A full
C++ compiler frontend is outside this bounded importer.

## Exact behavior and files

- `libs/types/src/header_import.cpp`: bind integral defaults in a parser with
  preceding `TemplateBindings`; resolve a template-template default naming an
  earlier template-template parameter, checking its destination shape normally.
  Nested parser contexts retain previously imported enumerator bindings, so
  supported enum names/namespace aliases remain available to those defaults.
  Retain the default's declaration namespace in private `TemplateParameter`
  metadata; type/integral defaults resolve names there when instantiated from
  another namespace. Preceding concrete arguments override lexical names;
  unrelated caller template bindings must not leak into default evaluation.
- Add right-associative `?:` and unary `!` to the shared signed integer
  evaluator. Parse both conditional branches; evaluate arithmetic only in the
  selected branch. Unknown names and malformed syntax still fail in either.
- Restore standard `sizeof...(Pack)` token order alongside type-form
  `sizeof(T)` / `alignof(T)`; use preceding type bindings for those queries.
- Single integer literal/forwarded value template arguments and defaults keep
  the full uint64 range until destination-width checking. Unrelated high-bit
  bindings must not poison signed expressions; using one in evaluated compound
  arithmetic remains an explicit overflow error.
- Update `docs/cpp-template-import.md`, `docs/header-import.md` and
  `docs/header-compound-pack-expansions.md` with examples and exact limits.

## Bounds and exclusions

Retain 32 template arguments/parameters, 4096 expression tokens/operations,
configured nesting/input/array bounds, nonnegative final non-type arguments,
and exact template-template shape checks. No expression deduction/inversion
extension, fold expressions, dependent member values, general `decltype`,
new declarators, simultaneous multi-pack expansion, or public API changes.

## Validation

No tests may be added or run in this session. Build `hexlab_types` and
`hexlab_cli` with `BUILD_TESTING=OFF`, desktop disabled, on Windows MSVC Debug
and WSL Ubuntu Clang Debug; record commands/results and review the diff.
