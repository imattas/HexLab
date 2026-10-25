# Partitioned stack memory SSA

`to_ssa` retains its whole-memory versions and adds independent version chains
for concrete stack slots proven by `recover_stack_variables`. The proof uses
the existing frame-pointer/adjusted-stack-pointer alias analysis, rejects
dynamic indexed frames and escaped frame addresses, and excludes overlapping
or conflicting-width ranges. Each accepted local has a deterministic partition
identity. A load carries its whole-memory version plus its partition identity
and partition version; a store carries the same partition identity and local
input/output versions. Join blocks receive a versioned phi for each written
partition.

The alias rule is byte-range based: two accesses share a partition only when
stack recovery resolves them to the same exact, non-overlapping local slot.
Stores to another proven slot do not change that partition's version. A store
that cannot be assigned to a proven slot advances every partition, as do all
calls and intrinsics with write or unknown memory effects. These effects also
advance the existing whole-memory chain. Read-only and no-memory intrinsics do
not invalidate partitions. This preserves ordering for aliases that fall back
to ordinary memory SSA.

Partition construction is bounded to 128 slots, 2,000,000 partition version
events, and 65,536 phi inputs. If the partition count or work budget is
exceeded, the function retains only whole-memory SSA. If stack recovery cannot
prove a slot, that access also remains on the whole-memory chain.

This first version does not partition globals, heap allocations, arbitrary
pointer aliases, or partial byte ranges. It adds local alias facts to the IR;
passes that do not inspect `memory_partition` continue using the coarser
`memory_version` dependency. No test suite is added or run as part of this
compile-only work.
