# ASCII case-insensitive text search

`TextQuery::case_sensitive` controls ASCII-only case matching. When false,
ASCII letters in the query match either uppercase or lowercase in the selected
encoding. This applies to ASCII bytes embedded in UTF-8, UTF-16LE/BE, and
UTF-32LE/BE encodings.

Non-ASCII Unicode scalars remain exact byte encodings; the search does not
perform Unicode case folding, normalization, locale rules, or multi-scalar
case expansions. The query still uses the ordinary bounded streaming byte
search, so continuation cursors, page limits, effective patched bytes, and
address mapping have the same behavior as case-sensitive text search.

The compiled pattern represents ASCII case pairs with a bit mask, so query
fingerprints distinguish case-sensitive patterns from patterns whose ASCII
letters can match either case. Text queries containing no ASCII letters have
the same effective pattern regardless of this option.
