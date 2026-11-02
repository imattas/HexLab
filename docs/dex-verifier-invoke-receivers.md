# DEX verifier invoke receiver checks

The bounded DEX register type-flow checks a receiver against the owner type of
the referenced method when both the receiver descriptor and owner are known.
An in-image hierarchy walk rejects only a proven mismatch; missing external
hierarchy nodes, null, and unknown descriptors remain conservative. A bounded
walk that cannot complete also remains unresolved.

This includes `invoke-polymorphic` (`0xfa`/`0xfb`): the receiver is checked
against the owner on its method identifier, while the separate call-site
prototype continues to determine argument and result types. The verifier does
not impose this method-owner check on `invoke-custom`, whose call site has no
receiver. These checks preserve the existing verifier worklist bounds,
cancellation, and instruction/method provenance on malformed results.

Known reference values are also checked against object field-store, invocation
parameter, and method return descriptors. The bounded in-image hierarchy and
array rules reject only a proven incompatible assignment; unknown values,
null, and unresolved external hierarchy relationships remain conservative.

## Instance field owners

For standard instance field gets and puts (`iget*`/`iput*`), a known
initialized receiver descriptor is checked against the declaring class of the
referenced field. The same bounded in-image class/interface walk and array
assignability rules used for method receivers apply. A proven mismatch rejects
the method with method index, code-item file offset, instruction code-unit
offset, and field index in the diagnostic. A null/unknown receiver or an
unresolved external hierarchy relation is not rejected; when a known relation
is unresolved, only the receiver's exact descriptor fact is discarded.

The existing constructor-only exception for `uninitialized-this` accessing a
field declared by its own class remains intact. Other uninitialized references
are not accepted as instance-field receivers. Optimized quick/volatile field
opcodes do not have resolved field-owner checks in this pass.
