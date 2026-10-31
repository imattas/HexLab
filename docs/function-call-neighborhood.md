# Function call neighborhoods

The Graph view offers a **Function callers and callees** mode alongside a
function's control-flow graph and the image-wide call graph. Select any
instruction owned by a recovered function and the view centers that function,
then includes its known callers and callees up to the selected call depth (1,
2, 3, 4, 8, 16, or 32). The depth control rebuilds the neighborhood without changing the
selected function. It keeps calls and tail
transfer candidates incident to the selected function, including external
import nodes and unresolved indirect-call nodes. Other image functions are
omitted, so the view stays useful when the whole-image graph is too large.

At each hop, both caller and callee edges are followed. The graph displays
known call and tail-transfer edges whose endpoints are in the resulting
neighborhood, plus unresolved/external endpoints reached from included
functions. It does not expand beyond the chosen depth. As with the image-wide graph,
edges come from current reference facts and function ownership. For native
memory-form calls whose decoded effective address exactly matches one
unambiguous loader-reported import slot, the `FunctionCall` record now retains
the import's library and name or ordinal as an external endpoint. This does not
read the slot's runtime contents or infer a local executable target. Register
indirect calls, dynamically computed slots, and conflicting import metadata
remain unresolved. Partial analysis or graph budgets
are represented in the model's completeness and omitted counts. Selecting a
location without a recovered function produces a clear request error rather
than an empty graph.

The same neighborhood is available from the project CLI:

```powershell
./hexlab_cli.exe project graph sample.hxproj --kind function-calls --at va:0x140001000 --depth 2 --format json
```

The selected address may be any instruction owned by a recovered function.
Depth is bounded to 1 through 32, while node and edge budgets cap large output;
the JSON/DOT graph model reports omitted nodes or edges when a cap is reached.
`--kind call` continues to mean the image-wide call graph.

The analysis API uses `GraphKind::function_calls` with the selected
`FunctionId` and `GraphOptions::call_depth` (bounded to 1–32). The project graph
service resolves a selected virtual address to its owner before building the
model. JSON exports report `function_calls` as the graph kind.

The shared layout condenses cycles into strongly connected components, assigns
the resulting acyclic graph to ranks, then performs four bounded downward and
upward barycenter passes to reduce crossings between adjacent ranks. Barycenter
comparisons use exact integer ratios and stable ties, so the same graph always
receives the same layout regardless of input vector order. SCC member order
remains stable; only the vertical order of components in a rank is adjusted.
