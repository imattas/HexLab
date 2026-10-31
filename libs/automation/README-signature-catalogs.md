# Native function catalogs

The native automation SDK exposes the same bounded function catalog workflows
as Python: selected recovered functions can produce target-scoped byte
signatures or normalized instruction fingerprints, and signature catalogs can
be recognized without changing project annotations.

`Project::function_signature_catalog` and
`Project::function_fingerprint_catalog` accept 1–4,096 unique function IDs in
caller order. They return the analysis library's typed catalog; use
`serialize_signature_catalog` or
`serialize_function_fingerprint_catalog` to persist its versioned format.
`Project::recognize_function_signatures` accepts serialized catalog text capped
at 64 MiB and returns explicit candidate and ambiguity rows. It caps returned
matches at 4,096. These operations are read-only and thread-affine.

Pass the current `edit_revision` as `expected_revision` to reject a stale
selection. The service also compares edit and byte revisions after extraction
or recognition, so a concurrent project change fails the full operation.
Cancellation is checked while analysis runs. Duplicate, stale, or
un-fingerprintable selected functions fail the whole catalog request; rows are
never silently dropped.

`examples/function_catalog.cpp` shows whole-project catalog creation with a
hard 4,096-function bound:

```text
hexlab_function_catalog signature sample.hxproj
hexlab_function_catalog fingerprint sample.hxproj
```

Build the example with `HEXLAB_BUILD_AUTOMATION_EXAMPLES=ON`. It writes the
serialized catalog to standard output, which can be redirected by the caller.
