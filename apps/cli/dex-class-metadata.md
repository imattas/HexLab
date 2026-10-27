# DEX class metadata in CLI inspection

The normal project inspection output and the DEX report path include a
`DEX class definitions` section. Each class row identifies its type-table index,
access flags, optional superclass index, and declared member totals. Static and
instance fields and direct and virtual methods are listed by their identifier
table indexes with raw access flags; methods also show their code-item offset
(zero when no code item is present).

Names are not copied into the shared metadata model, so this report uses table
indexes rather than resolving class or member names. Type indexes refer to the
DEX type-id table; field and method indexes refer to their respective tables.

Output is bounded to the first 256 class definitions and 128 rows in each
member category per class. The report prints total counts and explicit omitted
counts when those limits truncate the listing.
