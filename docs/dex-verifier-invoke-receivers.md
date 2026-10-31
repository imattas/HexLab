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
