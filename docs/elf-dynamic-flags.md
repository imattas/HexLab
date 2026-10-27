# ELF dynamic flag tags

The dynamic table parser recognizes `DT_FLAGS` (30) and `DT_FLAGS_1`
(`0x6ffffffb`) as singleton scalar tags. Their raw integer values and source
indices remain available in `ElfDynamicEntry`; duplicate instances are
rejected under the dynamic-table singleton rule. Recognizing these tags keeps
them from making the dynamic table's recognized-tag completeness status
partial.

The loader does not yet decode individual flag bits or apply their runtime
effects. In particular, this metadata is not a security-policy assessment and
does not implement loader behavior such as text-relocation policy, symbolic
lookup, or immediate binding.
