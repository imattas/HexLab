# Composing FLAIR catalogs

The C++ analysis API can recognize several independent FLAIR catalogs against
one image in a single bounded pass. This is useful when a project uses separate
catalogs for compiler runtimes, operating-system libraries, or vendor code.

Each catalog keeps its own provenance and pattern order. Recognition does not
merge or deduplicate the catalogs. Candidates retain the input `catalog_index`
and provenance, and repeated patterns contribute to that catalog's
`matching_patterns` count. Different candidate names remain explicit
ambiguity; equal names from different catalogs remain separate evidence rows.

Every catalog must target the image's exact architecture and execution mode.
The combined set is limited to 256 catalogs and 65,536 total patterns by
default. Candidate, comparison, reference-resolution, function, and result
limits are shared across the whole recognition operation. A reference record
may resolve to a grounded function name from any catalog in the set. Cycles
without a grounded name still do not bootstrap into matches.

```cpp
auto runtime = parse_flirt_pat(runtime_pat, image.layout().architecture,
                               image.layout().mode, "runtime catalog");
auto vendor = parse_flirt_sig(vendor_sig, "vendor catalog");
if (!runtime) return runtime.error();
if (!vendor) return vendor.error();
const std::array catalogs{std::move(runtime.value()), std::move(vendor.value())};
auto recognition = recognize_flirt_catalogs(
    image, *effective_bytes, functions, catalogs);
```

The existing `recognize_flirt_catalog` overload remains available and behaves
like a one-catalog set with index zero. There is no combined catalog file
format; callers parse each `.pat`, `.pat.gz`, or `.sig` independently. The CLI
accepts one catalog with `--definitions` or an ordered catalog list with
`--definitions-list`; both commands share aggregate input, pattern, candidate,
comparison, and result limits. The desktop **Scan FLAIR Catalogs and Browse
Results...** command provides an ordered list: files can be added repeatedly,
removed, or moved before one evidence result is stored for the entire set. It
accepts at most 256 entries, 64 MiB of total source bytes, 64 MiB of inflated
catalog bodies, and 65,536 patterns. Each file is parsed independently under
the remaining aggregate budgets, and its filename is retained as provenance.
Reading and hashing files checks the worker's cancellation request in bounded
chunks; parsing and recognition receive the same stop token. The ordered digest
includes each length-prefixed filename provenance and raw file content, so
catalog order and duplicate selections remain distinct evidence inputs.
The Python automation API accepts
ordered `(bytes, provenance)` pairs through `Project.recognize_flirt_catalogs()`
and returns detached candidates without persisting evidence. Candidate
`catalog_index` values refer to input order, starting at zero. Neither the
read-only APIs nor desktop scan automatically rename functions; applying
labels remains an explicit operation.
