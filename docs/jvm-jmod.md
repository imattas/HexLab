# JMOD containers

The JMOD loader accepts the version 1.0 `JM\x01\x00` header and parses the
following bytes with HexLab's bounded ZIP32/ZIP64 reader. Existing archive
limits apply to the embedded ZIP data, and extracted class members retain the
ZIP reader's size and CRC checks.

Each ZIP member is retained with its archive index, section, and path relative
to that section. The known sections are `classes`, `conf`, `headers`, `legal`,
`lib`, `bin`, `include`, and `man`. Unknown section names remain visible as
`unknown` for inspection rather than being treated as class files.

`load_jmod_class` accepts a slash-separated JVM internal class name, finds an
exact `<name>.class` member under `classes/`, and passes it through the normal
bounded class-file loader. Missing or duplicate class paths are reported. This
does not perform module-path resolution, native library loading, signature or
module hash verification, filesystem extraction, or support JMOD versions
other than 1.0. JMODs are transport/link-time containers and are not treated as
runtime class-path archives.

The JMOD header and section convention follow the [Oracle `jmod` tool
documentation](https://docs.oracle.com/en/java/javase/21/docs/specs/man/jmod.html).
