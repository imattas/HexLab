# ARM ELF EHABI function roots

The ELF loader reads linked ELF32 ARM `.ARM.exidx` tables as function entry
evidence. It accepts little-endian ET_EXEC and ET_DYN images, decodes each
PREL31 function address relative to the address of its word, and requires the
result to identify initialized executable bytes. Entries must be strictly
ordered, and table sections must be allocated initialized data with complete
eight-byte rows. The reader applies the normal shared metadata budget and
publishes the parsed rows only after the table has been accepted.

Each accepted row seeds a function root with its exidx section and exact row
file extent retained as provenance. The low bit of the PREL31 start selects
Thumb or A32 mode; a root is retained only when that state agrees with the
mapped ARM context. This entry state also supplies the known-clear Thumb IT
state needed to start analysis at that root.

The loader records whether the recipe is `cantunwind`, inline compact, or an
extab reference. For extab references it validates and retains the referenced
word and source location. It does not interpret unwind opcodes, personality
routines, exception data, or recover caller registers. Relocatable ET_REL
tables are skipped because their PREL31 relocations have not been applied.

An exidx row proves an entry, but does not provide an exact body extent. The
analysis therefore does not use the next row as a function end and does not
constrain decoding to a guessed range. DWARF FDE ranges remain a separate
source when available. Malformed or unsupported EHABI tables produce loader
diagnostics and do not become roots.
