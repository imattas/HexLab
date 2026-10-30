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
`--definitions-list`. The desktop **Scan FLAIR Catalogs and Browse Results...**
command also accepts an ordered multi-file selection and stores one evidence
result for the entire set. Candidate `catalog_index` values refer to selection
order, starting at zero. Neither the API nor desktop scan automatically renames
functions; applying labels remains an explicit operation.
