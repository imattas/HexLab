# PE SafeSEH metadata

For PE32 images, HexLab reads the SafeSEH handler-table VA and count from the
versioned load-configuration fields at offsets 64 and 68. It normalizes the
table VA against the preferred image base, verifies that the full count of
four-byte entries fits the mapped image and the loader's record budget, and
requires each handler RVA to refer to initialized executable bytes. Handler
RVAs must be strictly increasing. Every accepted row retains the file spans
that backed its table entry, and the table fields retain their own source
spans.

The desktop PE Load config page displays the validated handler count and table
RVA. Its rows navigate to handler addresses and show the source file offset.
The parser only reads these fields when the declared load-config structure
contains both fields. PE32+ has no SafeSEH table fields, and the UI reports
SafeSEH as absent for such records. SafeSEH registration is metadata only;
HexLab does not execute or enforce the Windows loader's exception-handler
policy.
