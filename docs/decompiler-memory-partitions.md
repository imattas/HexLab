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
  origin through supported copies, constant or bounded-interval offsets, and
  unanimous phi inputs. A nonconstant same-width add/sub offset can widen the
  origin when integer value analysis proves one bounded unsigned interval
  without wrap. Subtraction reverses the interval endpoints before checked
  signed-offset accumulation. The interval analysis accepts complete SSA phis
  and checked arithmetic but does not infer bounds from path predicates. If
  its bounded fixed point does not converge, nonconstant ranges and derived
  pointer origins are discarded rather than using a finite approximation. For
  flat A32, AArch64, RISC-V,
  MIPS, and PowerPC register banks, a proven 32- or 64-bit constant register
  value is rooted at that numeric address. Equal constants in different
  registers therefore share one address origin, and differing constants
  become checked offsets from it. Values above the signed offset bound retain
  opaque roots. The generic x86 GPR bank is excluded because a segment override
  can change the effective address without changing the GPR value. Integer
  offsets are propagated from literals, same-width copies, unanimous phis, and
  checked same-width `add`, `sub`, or `mul` trees with no intermediate wrap,
  plus exact same-width `and`, `or`, and `xor` trees, all bounded to 32
  expression levels before pointer origins are solved, so an address
  expression such as `base + offset_register` can produce an exact range when
  that register has one proven value.
  The memory access may have no index register, or use an index whose exact
  constant is proven through a literal, same-width copy, unanimous phi, a
  checked same-width `add`, `sub`, or `mul` tree with no intermediate wrap, or
  exact same-width `and`, `or`, and `xor` trees, all bounded to 32 expression
  levels. It can also use a bounded unsigned interval proven by `index & mask`
  for any canonical same-width constant mask, or a complete phi
  whose incoming values all have known intervals. Same-width `add`, `sub`, and
  `mul` preserve intervals when endpoint checks prove every possible result
  stays within the bit width without wrap; subtraction additionally requires
  every possible left operand to be at least every possible right operand.
  Multiplication bounds the maximum product before computing either endpoint.
  Nonconstant intervals survive same-width SSA register copies and supported
  expression trees. Unsigned `udiv` and `urem` with a proven nonzero constant
  divisor bound an arbitrary same-width numerator: division uses the unsigned
  endpoint quotients, and remainder stays within `[0, divisor - 1]`. If the
  numerator already has a range contained in one quotient bucket, remainder
  preserves its tighter endpoint range; ranges crossing a divisor multiple
  use the enclosing zero-based interval. Divisor zero, variable divisors,
  mixed widths, and signed division/remainder do not produce these facts.
  A noncontiguous AND mask can leave holes; `[0, mask]` is a conservative
  envelope, not a claim that every offset is reachable. Available input
  intervals can further cap that envelope's upper endpoint.
  An interval widens the partition to include every possible indexed byte; it
  does not assert one runtime offset. Same-width unextended indices use
  nonnegative values.
  Explicit integer `zext`/`sext` assignments preserve index intervals across
  width changes. Sign-extended ranges that cross the source sign bit widen to
  the full target domain because they do not form one precise unsigned interval.
  AArch64 `uxtw`, `sxtw`, and `sxtx` indices use their architectural zero- or
  sign-extension before checked scale/shift and displacement arithmetic. The
  final byte range must fit the checked signed offset bounds. Pointer arithmetic
  also interprets bounded two's-complement offset ranges as signed displacements,
  including negative ranges produced by sign extension. A range crossing its
  sign bit widens to the full signed domain before the existing checked offset
  bound is applied.
  The access also needs a bounded byte width. Ranges sharing the same root
  register version and overlapping offsets
  are grouped together. Call results and call-clobbered register
  definitions are accepted as opaque roots, so accesses through a copied or
  constant-adjusted call output can use this partitioning too. These roots do
  not imply allocation freshness or disjointness: a store through a different
  root invalidates their partitions along with the other pointer-relative
  partitions.

Pointer-typed values loaded from an identical explicit absolute byte range at
the same whole-memory SSA version share a root, even when the destination
registers differ. The whole-memory version is captured before each
instruction and advances across every modeled store, call, and write-capable
intrinsic, so an intervening modeled write prevents this equality fact. This
models stable sequential memory represented by the IR; it does not cover
asynchronous external mutation or volatile/device memory, which the current
`MemoryValue` does not distinguish. Loads from dynamic source addresses,
non-pointer values, or different versions retain opaque roots. Equal loaded
roots permit same-root byte-range reasoning only; distinct opaque roots remain
may-alias and stores through them continue to invalidate each other's
partitions.

The alias rule is byte-range based. A store advances its exact stack or
absolute-range partition. An absolute-address store also invalidates stack and
pointer-relative partitions, plus any absolute partition not proven disjoint
by address space or byte range. A pointer-relative store advances every
partition that might alias it; it preserves another range only when the
partition has the same proven pointer root and its byte range is disjoint.
Different pointer roots are not assumed to be disjoint. Calls invalidate all
absolute and pointer-relative partitions while preserving proven nonescaping
stack slots.
Intrinsics with write or unknown memory effects and unclassified stores
invalidate every partition. These effects also advance the whole-memory chain.
Read-only and no-memory intrinsics do not invalidate partitions.

Candidate absolute and pointer-relative range sets are each capped at 4,096
ranges. The complete partition set is capped at 128 partitions, with 2,000,000
partition events and 65,536 phi inputs. If these bounds are exceeded, or a
range cannot be mapped to a proven partition, that access falls back to
whole-memory SSA. If whole-function partition construction exceeds its budget,
the function keeps only whole-memory SSA.

Constant and interval expression evaluations each visit at most 1,024 nodes
and descend at most 32 expression levels; a range evaluation shares these
limits with its constant subevaluations. Unsupported or over-budget
subexpressions yield no input interval; a mask or nonzero constant divisor can
still establish its independent enclosing bound. The existing 64-iteration
convergence gate discards nonconstant intervals on exhaustion.

For example, `slot = index % 12; copy = slot; address = base + copy * 4`
can prove offsets `[0, 44]` even when `index` has no known range. A four-byte
access covers `[0, 48)` relative to the same pointer root. A store at
`base + 64` may preserve that partition when the existing root/overlap checks
succeed. No object extent or safety of either runtime access is inferred.

This does not partition heap or global accesses whose address cannot be proven,
aliases reached through unrelated roots as disjoint, variable indices without
a supported bounded interval, unsupported index extensions, or pointer
arithmetic whose offset is neither a proven constant nor a supported bounded
integer interval. Bitwise and shift constant expressions are evaluated at their
declared width; shifts require a proven count below the width, while add/sub/mul
still require no intermediate wrap. Bounded unsigned index intervals also
propagate through constant-count shifts when the result remains ordered without
wrap; arithmetic right shifts that cross the sign boundary widen conservatively.
Signed index offsets are accepted only for the
listed AArch64 forms and only when checked arithmetic
does not overflow; wrapping address arithmetic remains unsupported. The IR
keeps these partitions supplementary: passes that ignore `memory_partition`
continue to use the coarser `memory_version` chain.
