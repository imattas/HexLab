# ELF differential oracle

`elf_oracle` builds authored C sources for i386 and x86-64 with the exact observed
test-only LLVM binaries bound by `tools.json`. The hashes identify the installed
binaries inspected on 2026-10-20; they are not a publisher signature. A missing,
changed, failing or malformed oracle is a failure, not a skipped comparison.
Python's standard library orchestrates these tests only. Production builds with
`BUILD_TESTING=OFF` have no dependency on Python, clang, lld or llvm-readobj.

The original C++ loader/analysis probe is compared with LLVM header, program,
section, symbol, raw relocation, dynamic string and dynamic-relocation facts.
The matrix includes authored 32/64-bit REL/EXEC/DYN, big endian, extended section
counts, unbounded dynamic symbols, independently compiled objects and linked
objects with both/GNU/SysV hashes, and copies with only section-header fields
cleared; debug EXEC/DYN with and without retained relocations; and a 4,100-function
sectioned object. Linked recovery must agree when static relocations are retained.
Original input bytes and all tool invocations/hashes are recorded in
the generated `elf-oracle/<configuration>/report.json`. ELF inputs are never
commands: the subprocess runner only accepts the designated tools, fixture
generator and original host probe. Compiled external calls must retain their
undefined symbol's relocation provenance without guessing a runtime library.

Observed LLVM output details are accounted for explicitly:

- JSON works for headers/programs/sections/symbols/section relocations. This
  build's `--dyn-relocations` output is not valid JSON even on exit 0, so that
  comparison uses expanded text with mandatory numeric type and symbol indexes.
- LLVM displays a section name for unnamed `STT_SECTION` symbols. Raw `st_name=0`
  remains an empty name in the original metadata; all raw symbol fields still
  compare exactly.
- For GNU-only sectionless inputs this build emits an empty `DynamicSymbols`
  array. Those symbol facts are compared against LLVM's original DYNSYM output
  after verifying exact header-only section removal, unchanged dynamic entries
  and identical symbol-table backing. This exception is recorded per input;
  headers, programs, dynamic strings and relocations are still inspected on the
  sectionless input directly. No symbol/relocation case is silently skipped.
- i386 `GLOB_DAT`/`JMP_SLOT` use `S`, so an initialized lazy slot is not treated as
  an implicit addend. Explicit RELA record bits are retained as declared. See
  [the primary x86 relocation table](https://docs.oracle.com/cd/E26505_01/html/E26506/chapter6-54839.html).

The verifier also rejects six deliberately forged header/symbol/relocation
projections, a missing tool, and malformed ELF accepted by either parser.
