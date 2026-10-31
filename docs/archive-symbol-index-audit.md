# Archive symbol-index audit

`hexlab_cli archive index-audit <archive> [--thin-root <directory>]` compares
the archive's parsed symbol-index rows with definitions found in ELF relocatable
members. It reports index rows that point at a member which does not define the
named symbol, missing index rows for ELF definitions, and rows that cannot be
verified because their member is not a supported ELF relocatable object.

The audit accepts GNU, BSD ranlib, and AIX big archive indexes through the same
bounded archive parser used by member selection. For GNU thin archives,
`--thin-root` is required; external paths remain confined to that explicit
root. Mixed-format archives are allowed, but index rows for non-ELF members are
reported as unverifiable because this audit does not infer COFF, Mach-O, or
XCOFF visibility rules.

The scan is capped at 4,096 archive members, 256 MiB of ELF member data, one
million defined symbols, one million index rows, and 64 MiB of decoded symbol
names. A zero exit status means an index is present and complete, with no
missing or stale rows for the audited ELF members. An absent or incomplete
archive index or any missing/stale row returns status 1. Unverifiable rows are
reported in the summary but do not change the status by themselves. The audit
does not modify the archive or rebuild its index.
