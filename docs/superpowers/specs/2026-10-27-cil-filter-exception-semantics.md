# Managed CIL filter exception semantics

## Scope

Model exceptions raised while evaluating a CIL filter as a false filter result. The active filter continuation must resume ordered search for the original exception after the filter clause. Explicit `throw` inside a filter follows this path; `rethrow` and nested exception regions inside filters remain unsupported.

## Approaches considered

- Reject every filter-body throw or possible exception. This avoids incorrect control flow but drops valid compiler output and contradicts CLR filter behavior.
- Send filter failures to ordinary method-level exception dispatch. This changes the exception being searched and can run the wrong handlers.
- Set the filter result to false and dispatch by the current filter continuation ID. This retains the original exception-search profile and metadata clause ordering, so it is selected.

## Design

For each filter body, collect all continuation IDs installed by the protected-try dispatch profiles and their corresponding filter decision blocks. A bounded synthetic block writes zero to the filter-result register and switches on the continuation ID to the correct decision block. Conservative exception edges from filter instructions target that block. Explicit `throw` remains an exception-producing terminator and gets the same route. `endfilter` retains its ordinary route. Existing profile dispatch continues to place outer `finally`/`fault` handlers after a selected catch or no-match result.

## Constraints

Throwability in a filter remains over-approximated for every instruction other than `endfilter`. Nested protected regions within filters, `rethrow` within a filter, CLR catch-token assignability, cross-method exception propagation, and a full runtime exception object model remain outside this change. No tests or builds are run by the implementation agent; root handles integration review.
