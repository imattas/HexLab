# Managed CIL function pointers

The managed CIL decoder recognizes `ldftn` and `ldvirtftn` and the method lifter models both as pointer-valued stack results. `ldftn` produces a symbolic method target using its metadata token. `ldvirtftn` consumes the receiver, emits a virtual target-resolution intrinsic, then leaves the resolved pointer on the evaluation stack. Both require a resolved method signature; `ldvirtftn` also requires an instance signature.

This allows the existing `calli` stack analysis to consume function pointers and preserve them as the indirect-call target. The current output does not reconstruct delegate creation, infer a callable prototype from the pointer value, or resolve a virtual target to a concrete implementation. The `calli` signature remains the authority for indirect-call argument and return stack effects.
