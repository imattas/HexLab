# Partitioned memory SSA

`to_ssa` retains whole-memory versions and adds independent partition versions
when it can prove enough about the accessed byte ranges. It still leaves the
whole-memory chain in place for consumers that need conservative aliasing.

The partitioner recognizes three bounded forms:

- **Stack slots:** `recover_stack_variables` proves exact, nonescaping,
  nonoverlapping frame-relative slots. Dynamic indexed frames and escaped frame
  addresses stay on whole-memory SSA.
- **Absolute ranges:** a memory access with an explicit absolute address and a
  byte-sized width of at most 256 bytes is grouped with overlapping ranges in
  the same address space. A load or store uses the resulting connected-range
  partition only when its exact byte range was observed and mapped.
- **Pointer-relative ranges:** a base register must have a proven SSA pointer
  origin through supported copies, constant offsets, and unanimous phi inputs.
  The memory access must have no index register and a bounded byte width and
  displacement. Ranges sharing the same root register version and overlapping
  offsets are grouped together. Call results and call-clobbered register
  definitions are accepted as opaque roots, so accesses through a copied or
  constant-adjusted call output can use this partitioning too. These roots do
  not imply allocation freshness or disjointness: a store through a different
  root invalidates their partitions along with the other pointer-relative
  partitions.

The alias rule is byte-range based. A store advances its exact stack or
absolute-range partition. A pointer-relative store advances every partition
that might alias it; it preserves another range only when the partition has
the same proven pointer root and its byte range is disjoint. Different pointer
roots are not assumed to be disjoint. Calls invalidate all absolute and
pointer-relative partitions while preserving proven nonescaping stack slots.
Intrinsics with write or unknown memory effects and unclassified stores
invalidate every partition. These effects also advance the whole-memory chain.
Read-only and no-memory intrinsics do not invalidate partitions.

Candidate absolute and pointer-relative range sets are each capped at 4,096
ranges. The complete partition set is capped at 128 partitions, with 2,000,000
partition events and 65,536 phi inputs. If these bounds are exceeded, or a
range cannot be mapped to a proven partition, that access falls back to
whole-memory SSA. If whole-function partition construction exceeds its budget,
the function keeps only whole-memory SSA.

This does not partition heap or global accesses whose address cannot be proven,
aliases reached through unrelated roots, indexed addressing, or arbitrary
pointer arithmetic. The IR keeps these partitions supplementary: passes that
ignore `memory_partition` continue to use the coarser `memory_version` chain.
