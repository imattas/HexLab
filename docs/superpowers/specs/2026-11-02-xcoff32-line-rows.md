# XCOFF32 line-row inventory design

Decode each section's six-byte line records after primary symbols have been inventoried. Retain the raw union word, raw 16-bit line value, source record offset and associated primary function slot. A zero line starts a function group and references a C_EXT, C_HIDEXT or C_WEAKEXT symbol defined in the owning section; nonzero rows require a preceding marker and contain virtual instruction addresses. Check marker symbol values and instruction addresses against the owning virtual section extent. Do not require the optional n_type function bit, infer function lengths, require address/line ordering, or resolve absolute source lines/include-file contexts.

Use the existing aggregate max_line_numbers and shared metadata-byte budget for reads and retained vectors; poll cancellation per row. Expose rows through xcoff32 inspect. Archive indexing and XCOFF64 remain unchanged. Source: IBM AIX 7.3 XCOFF object file format, Line Number Information and Symbol Table Information: https://www.ibm.com/docs/en/aix/7.3.0?topic=formats-xcoff-object-file-format

The user authorized direct execution, no tests, no CI and no push. Verification is Windows and WSL local builds with BUILD_TESTING=OFF.
