# Signature Catalog Composition

## Intent

Analysis callers should be able to compare one image against several independently maintained byte-signature catalogs in one bounded recognition operation. This is useful for combining application, compiler-runtime, and vendor-library definitions without merging source files or renaming duplicate candidates.

## Goals

- Accept an ordered span of existing `SignatureCatalog` values for executable scanning and recovered-function recognition.
- Check every version-2 catalog against the image architecture and execution mode before scanning.
- Preserve each candidate's source catalog index and its global definition index in results.
- Apply one shared candidate/comparison/result/scanned-byte budget across the composition.
- Preserve duplicates and input order so ambiguity remains explicit.

## Non-goals

- No new on-disk catalog-set format or CLI flags in this pass.
- No automatic renaming or preference between matching catalogs.
- No change to legacy definition-file or single-catalog APIs.
- No test additions or test execution under the active workspace constraint; the change is compile-only integrated by the parent agent.

## Approaches

1. Serialize a merged catalog. This fails for duplicate names, loses which source catalog supplied a candidate, and makes legacy target scope ambiguous.
2. Add a catalog-set format. This provides persistence, but creates a new parser/writer and migration surface before a user can compose catalogs in the library.
3. Add in-memory multi-catalog scan and recognition overloads. This reuses the existing bounded scanner once, keeps source catalogs independent, and reports global plus per-catalog identity. This is the chosen approach.

## Design

Append `catalog_index` to `SignatureMatch`; existing overloads leave it zero. New overloads accept `SignatureCatalogSet`, validate catalog versions and every v2 target, concatenate definitions in catalog order, and run the existing scanner exactly once. Total catalog count and total definitions are bounded; the existing scanner's limits therefore remain aggregate. Results map each global definition index back to its catalog index. Recognition uses the same combined scan and retains ambiguity as before.

Version-1/unscoped catalogs may be composed alongside a version-2 catalog. Their definitions are still scanned against the selected image; callers have explicitly chosen that image when invoking the API. Empty sets, unsupported versions, incompatible v2 targets, and aggregate definition overflow return errors before scanning.

## Implementation choices

- Maximum composition size: 256 catalogs and 4,096 total definitions, matching current bounded parser/scanner limits.
- Input order is retained; no name or pattern deduplication occurs.
- Existing APIs remain source-compatible through append-only metadata and overload additions.
- Root integration owns compile-only verification. No tests are added or run.
