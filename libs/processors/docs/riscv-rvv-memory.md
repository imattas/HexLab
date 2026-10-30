# RISC-V vector memory operations

The RV64/RV32 static decoder accepts integer RVV unit-stride, strided, and
indexed memory forms with one through eight fields. The decoded instruction
stores the field count in `vector_segment_fields`; ordinary single-field
operations use one. Fault-only-first, whole-register, and mask transfers remain
unsupported.

The processor semantic planners accept the same field count. They return one
address entry for each active `(lane, field)` pair, ordered by lane and then by
field. Unit-stride accesses interleave fields within each lane; strided and
indexed accesses offset each field by its element size from that lane's
address. Masked-off lanes and lanes before `vstart` produce no entries. Plans
reject address wrap, invalid field counts, unsupported EEW/SEW/EMUL values, and
segment groups whose `NF * EMUL` exceeds eight registers.

These planners expose candidate addresses only. They do not model memory
faults, partial completion, fault-only-first `vl` updates, register-group
overlap, or the vector register data transfer itself.
