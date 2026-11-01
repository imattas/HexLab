# JVM Code static operand constraints

The classfile loader checks method-local operand constraints during its bounded
`Code` scan, before publishing the method's address space. The shared decoder
still accepts context-free encodings; the loader supplies the owning method,
constant pool and actual `Code.max_locals`. These checks also apply when the
method has no `StackMapTable`, and to instructions that may be unreachable.

The scan checks the following constraints:

- Descriptor parameters, including an instance receiver and the second slot of
  every `long` or `double`, must fit `max_locals`.
- Every local load/store, `iinc` and legacy `ret` must fit the actual local array.
  Explicit byte indexes, implicit `_0` through `_3` indexes, and `wide` indexes
  use the same check. Category-2 accesses require two slots; an access at slot
  zero is checked even when `max_locals` is zero.
- All six return opcodes must match the declared return category. `ireturn`
  accepts boolean, byte, char, short and int descriptors; `areturn` requires a
  reference or array result. The result category comes from the descriptor
  parser, so unusual legal class names containing parentheses cannot change
  which descriptor type is selected.
- `new`, `anewarray`, `checkcast`, `instanceof` and `multianewarray` must reference
  `CONSTANT_Class` entries with valid internal class names or array descriptors.
  `new` cannot name an array. `anewarray` cannot add a dimension to an existing
  255-dimensional array. `multianewarray` requires an array descriptor with at
  least its nonzero encoded number of dimensions; allocating fewer than the
  descriptor's total rank remains legal.
- A constructor reference may be invoked only by `invokespecial`. Existing
  opcode-specific method-reference tags and `invokeinterface` argument-slot
  checks still apply. Class constants loaded with `ldc`/`ldc_w` require classfile
  version 49 or later; existing constant category/version checks remain active.

An invalid constraint produces `ErrorCode::malformed`; unsupported instruction
encodings remain explicitly unsupported, and cancellation propagates. There is
no second unbounded pass or class search: work remains bounded by the existing
65,535-byte method extent and classfile/metadata limits. Stack-map parsing uses
the same class-context scan when it needs instruction boundaries.

These checks implement part of the
[JVMS static and structural constraints](https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.9),
not a complete verifier. A separate bounded [stack and local analysis](jvm-operand-stack-verification.md)
checks reachable stack transfers and primitive/reference local categories
across CFG and exception edges. It tracks descriptor-initialized parameter
slots, stores, category-2 overlap and uninitialized local reads for the
implemented transfer subset. A successful load still does not prove reference
assignability, constructor alias transitions, required stack-map coverage,
access control or runtime member resolution. An `areturn` category match does
not prove assignability. A class-name match does not prove a defining loader or
an available hierarchy. Consumers that require those facts must keep missing,
ambiguous or incomplete hierarchy evidence unresolved and reject an operation
whose safety requires such a proof.
