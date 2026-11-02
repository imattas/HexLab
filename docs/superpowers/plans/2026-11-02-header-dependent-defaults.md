# Header Dependent Defaults Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Prior authorization explicitly excludes tests and approval pauses.

**Goal:** Complete preceding-argument binding for supported template defaults and their bounded conditional expressions.

**Architecture:** Keep concrete bindings in nested parser contexts. Extend the shared integer evaluator, preserving normal argument-kind/width and resource validation.

**Tech Stack:** C++20, CMake, MSVC, WSL Ubuntu Clang.

**Spec:** `docs/superpowers/specs/2026-11-02-header-dependent-defaults.md`

## Global Constraints

No tests added or run; `BUILD_TESTING=OFF`; no pushes or CI. Own only
`libs/types/` and header-import documentation. Preserve 32 argument/parameter
and 4096 expression token/operation caps and configured nesting/input bounds.

## Review Focus

Conditional associativity/precedence and skipped arithmetic; sizeof pack token
order; type/template defaults using preceding bindings; unrelated high-bit
arguments versus evaluated signed arithmetic; destination kind/width checks.
Review these statically because this session excludes test execution.

### Task 1: Shared expression and binding implementation

**Files:** Modify `libs/types/src/header_import.cpp`.

**Interfaces:** Private `IntegerExpressionParser::parse_conditional(unsigned,
bool) -> int64_t`; `Parser::evaluate_template_integer_argument(const
vector<Token>&, const map<string,uint64_t,less<>>&) -> uint64_t`;
existing `Parser::bind_template_parameters(...) -> TemplateBindings` and
`Parser::parse_template_parameters(bool) -> vector<TemplateParameter>`.
Private `TemplateParameter::default_namespace_stack` retains the declaration
namespace used by type/integral default parser contexts;
`default_aggregate_scopes` prevents inheriting caller aggregate lookup scopes.
Private `Parser::template_default_context(const TemplateParameter&, const
TemplateBindings&) -> Parser` applies the lexical scope and replaces caller
template bindings with only the preceding bindings of the destination.

- [x] Add conditional-expression parsing and unary logical negation, preserving short-circuit parsing and resource bounds.
- [x] Correct sizeof pack grammar; defer unsigned-binding range checks until evaluated use.
- [x] Preserve full-range direct literals/value forwarding; bind defaults with preceding type/value/template/pack contexts; resolve preceding template-name defaults.
- [x] Review each input class in Review Focus against the complete diff.
- [x] Capture each default's declaration namespace; restore it for type/integral default lookup during instantiation from other namespaces.

### Task 2: Documentation and build verification

**Files:** Modify `docs/header-import.md`, `docs/cpp-template-import.md`,
`docs/header-compound-pack-expansions.md`; record builds here.

- [x] Document dependent defaults, conditional expressions, short-circuit limits and full-range forwarding.
- [x] Configure Windows: `cmake -S . -B out/build/header-defaults-win -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=OFF -DHEXLAB_BUILD_DESKTOP=OFF`.
- [x] Build Windows: `cmake --build out/build/header-defaults-win --config Debug --target hexlab_types hexlab_cli --parallel 4`.
- [x] Configure WSL Ubuntu (login shell): `cmake -S /mnt/g/HexLab/.worktrees/header-binding-nov02 -B /tmp/hexlab-header-defaults-nov02-make -G "Unix Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=OFF -DHEXLAB_BUILD_DESKTOP=OFF -DHEXLAB_ENABLE_PINNED_LLVM_ORACLES=OFF`.
- [x] Build WSL (login shell): `cmake --build /tmp/hexlab-header-defaults-nov02-make --target hexlab_types hexlab_cli --parallel 4`.
- [x] Record results; `git diff --check`; commit locally and report remaining unsupported forms.

## Execution notes

Managed worktree creation stalled; git fallback created
`G:/HexLab/.worktrees/header-binding-nov02`, branch
`codex/header-binding-nov02`, base `b60394af`.

WSL direct `cmake` invocation failed because only the login-shell PATH includes
`/home/imattas/.local/bin`; the initial Ninja configure then failed because Ninja
is absent. The actual fallback configure/build uses `wsl -d Ubuntu-24.04 -- bash
-lc '...'`, generator `Unix Makefiles`, build directory
`/tmp/hexlab-header-defaults-nov02-make`, and otherwise the flags above.
No tests were added or run. Static review used the Review Focus list; independent
review is delegated to the parent before integration because all agent slots
are occupied.

Windows configure exited 0 (MSVC 19.44.35229, SDK 10.0.26100.0).
The complete `hexlab_types` / `hexlab_cli` build exited 0; a final invocation
after the last source edit also exited 0. Logs:
`out/build/header-defaults-win/build.log` and `build-final.log` in that directory.
Existing DLL-interface, shadowing, conversion and initializer warnings remain.

WSL Ubuntu 24.04 configure exited 0 (Clang 18.1.3, Unix Makefiles).
The complete `hexlab_types` / `hexlab_cli` build exited 0. The final invocation
recompiled `header_import.cpp`, relinked the type library and dependent CLI,
and exited 0. Logs in WSL:
`/tmp/hexlab-header-defaults-configure-make.log`,
`/tmp/hexlab-header-defaults-build-make.log`, and
`/tmp/hexlab-header-defaults-build-final.log`.
Both caches retain `BUILD_TESTING=OFF`; no tests, CI or push were performed.
`git diff --check` passed.

Residuals: general C++ deduction/two-phase lookup, dependent parameter types
and member-value expressions, unsigned compound arithmetic, simultaneous
multi-pack/nested-ellipsis expansions and broader declarations/attributes remain
outside this bounded importer. This change does not make `types.headers` complete.
