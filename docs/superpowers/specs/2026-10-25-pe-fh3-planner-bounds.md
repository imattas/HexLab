# PE FH3 Exception Planner Bounds

## Intent

Make the public FH3 exception planning API robust when callers provide constructed or modified `PeMetadata`, not only metadata produced by the validated PE parser.

## Goals

- Bound planner work and output sizes independently of parser provenance.
- Validate ordering, function ownership, state references, and handler/action inputs before using them.
- Preserve advisory candidate semantics; never execute target code or claim runtime-equivalent dispatch where metadata order is uncertain.

## Non-goals

- Implementing the Microsoft C++ exception runtime or invoking cleanup/handler code.
- Changing FH3 parsing, persisted formats, or existing parsed-image behavior.

## Approaches

1. Trust all parser invariants. This is fast but unsafe for public caller-owned metadata.
2. Revalidate bounded planner inputs and return diagnostics on malformed/oversized data. **Selected** because the API accepts public metadata structs.
3. Make the metadata model private. This is a broad API break.

## Constraints

- Keep the existing C++ image API and conservative dispatch dispositions.
- Do not add or run tests in this wave; compile affected Debug targets and inspect source paths.
- Leave `out/` untouched and do not launch the desktop.
