# Sequential nested-loop conditional joins

1. Replace the single optional child conditional region with an ordered list.
2. Validate each sequential branch/arm/join region without reusing blocks.
3. Emit each branch once, its arm blocks once, and its phi copies on the matching
   edges; emit the join through the normal child-body walk.
4. Update structuring documentation and record source-level checks. Do not add
   or run tests/builds in this task.
