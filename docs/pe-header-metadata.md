# PE COFF and optional-header metadata

The PE loader retains the COFF timestamp and characteristics plus standard
optional-header version fields, DLL characteristics, stack and heap reserve /
commit sizes, loader flags, and the declared RVA-directory count. These values
are metadata only: the loader does not infer a build date from the timestamp,
apply loader policy from the characteristics, or treat reserved/unknown flag
bits as security guarantees. The CLI `inspect` output prints the raw COFF and
DLL characteristic masks, version tuples, resource sizes, directory count, and
file-offset provenance for the COFF characteristics and optional header.

The directory count is read from the PE32 or PE32+ location and remains subject
to the existing strict check that every declared eight-byte directory entry
fits within `SizeOfOptionalHeader`. All source offsets are derived from the
validated COFF and optional-header positions.
