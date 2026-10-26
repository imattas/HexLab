# ELF ARM EHABI function roots

For linked little-endian ELF32 ARM `ET_EXEC` and `ET_DYN` images, the loader
accepts allocated initialized `.ARM.exidx` rows (including sections identified
by `SHT_ARM_EXIDX`). It decodes each function start as a signed PREL31 value
relative to the first word, clears the ARM/Thumb address-state bit for the
analysis entry, and requires the entry to lie in initialized executable image
memory. Starts across the table sections must be strictly increasing.

Each accepted row retains its original section, file offset, two raw words,
and recipe classification (`cantunwind`, inline compact, or extab reference).
An extab reference is retained only when it is word aligned and identifies a
word inside an allocated initialized `.ARM.extab` section; the raw first extab
word and its section/file provenance are retained. The loader does not decode
the EHABI bytecode or personality-specific extab payload.

Validated rows seed function entries with their eight-byte table-row evidence.
The next row is not used to claim a function size or chunk because EHABI table
ordering does not establish a trustworthy extent for every function. ET_REL
tables are unsupported until their PREL31 relocations are applied. Malformed,
out-of-range, unordered, or unsupported tables are rejected as a unit and
reported through the loader's partial-metadata diagnostics.
