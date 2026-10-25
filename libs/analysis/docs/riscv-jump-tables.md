# RV64 absolute-pointer switch tables

Switch analysis recognizes the exact RV64 dispatch shape:

```text
slli index, selector, 3
add  address, table_base, index
ld   target, 0(address)
jalr x0, 0(target)
```

The `slli` may be separated from the adjacent `add`/`ld`/`jalr` by a short straight-line sequence, provided the sequence stays in the same recovered basic block and no instruction rewrites the scaled index or selector. The table base must be the most recent definition of its register in the nearby instruction window and must come from `auipc` or an adjacent `auipc`/`addi` pair. Where relocation metadata resolves the pair, the relocation target is used; otherwise the decoded signed immediates are combined.

Each entry is read as an eight-byte absolute target using the image's byte order and relocation resolver. The target must be a decoded instruction in executable, file-backed RV64 bytes. Scanning is capped at 4096 entries. An invalid or unreadable entry ends the recovered prefix and marks the site incomplete. This form does not yet infer an RV64 case count/default edge from `bltu`/`bgeu` guards, and signed four-byte relative-offset tables, RV32 tables, compressed predecessor instructions, arbitrary register propagation, and loop-carried setup remain unresolved.
