# Desktop string browser

The Metadata notebook's Strings page filters discovered strings by preview text, mapped address or file offset, and encoding. The split view shows the selected string's incoming references and supports bounded paging; activating a string navigates to its data, while activating a reference navigates to its source.

Incoming references use the current project `ReferenceIndex`. Mapped strings query the file range together with virtual aliases; strings without a mapped address query the file range directly. Results are paged in groups of 128. Stale and pending analysis does not show old reference rows, and incomplete analysis is labeled. Standalone documents without a project reference index still support string filtering and navigation, but cannot browse references.
