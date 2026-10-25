# String reference validation

`find_string_references` joins a derived `ReferenceIndex` with a `StringScan`.
Each resolved reference target inside a discovered string's byte extent yields
one result containing the reference identity, source, operand index, reference
kind, and string-record index. Address targets match only strings mapped into
the same address space; file-offset targets work for strings without a virtual
mapping. Interior pointers are retained. External and unresolved targets do
not produce a match. Overlapping string candidates can each match the same
target, preserving the scan's encoding ambiguity instead of selecting one.

Completeness follows both inputs: a truncated reference index or budget-limited
string scan makes the result partial. Cancellation and allocation failures are
reported as errors. Results are deterministic by source, operand, reference,
and string order. The output is capped at four million matches and reports
partial status when that budget is reached. This pass matches targets within recognized string extents;
it does not infer pointers from raw bytes or resolve dynamic register values.

Validation: `string_reference_tests` covers interior address and file-offset
targets, external target exclusion, incomplete input propagation, and
cancellation.
