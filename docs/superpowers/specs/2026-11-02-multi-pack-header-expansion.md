# Zipped C++ Template Pack Expansion

Header import should expand a compound template argument pattern that mentions multiple bound parameter packs when all participating packs have equal lengths. Expansion is element-wise: the first element of each pack substitutes together, then the second, and so on. Different lengths are malformed input; an empty pack emits no arguments. Existing argument-count and nesting bounds continue to apply.

This slice does not implement nested ellipses, pack-length operators, or general C++ template deduction. Unsupported forms remain explicit and do not produce guessed types.

Validation: build `hexlab_types` and `hexlab_cli` on Windows and WSL with tests disabled; do not run tests.
