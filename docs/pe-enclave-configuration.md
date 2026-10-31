# PE enclave configuration

The load-configuration reader follows a nonzero `EnclaveConfigurationPointer`
for both PE32 and PE32+ images. `PeLoadConfiguration::enclave_configuration`
retains the configuration RVA, declared and minimum required sizes, policy
flags, family and image IDs, image/security versions, private address-range
size, thread count, enclave flags, and import-table RVA/count/stride.
PE32 uses the 76-byte configuration layout and PE32+ uses the 80-byte layout;
only the latter has an eight-byte `EnclaveSize`.

Each `PeEnclaveImport` preserves the raw match type, minimum security version,
32-byte unique/author ID, 16-byte family and image IDs, reserved DWORD, import
name RVA, and terminated name bytes. Configuration, table, individual record,
and name spans retain original file provenance. Import-table addresses and
names are RVAs, even in PE32+ images. The containing load-configuration pointer
is a preferred-base VA that the existing reader normalizes before decoding.

The parser validates initialized image coverage for the complete declared
configuration and import table. It requires an eight-byte size prefix and a
minimum required size between eight and the declared size; a zero minimum
means eight bytes. Configurations shorter than the supported fixed layout or
requiring a larger layout have `unsupported` status. Larger optional tails
and import strides are accepted with source provenance but remain opaque.
Only the known 80-byte import prefix is materialized.

Inspection limits are one MiB per configuration, 4096 import records, 16 MiB
for the import table, 4096 bytes including the terminator per name, and one
MiB including terminators across names. Nonempty tables require a nonzero RVA
and a stride of at least 80 bytes. Names must be nonempty and terminated in
initialized image bytes within the budgets. Cancellation propagates to the
loader. Unknown policy bits, match types, and reserved values remain raw
metadata rather than being assigned unsupported semantics.

All import rows are published together after successful decoding. Malformed,
unsupported, or over-budget enclave structures retain an explicit status and
diagnostic while preserving the enclosing load configuration and mapped image.
The loader emits a warning and marks metadata incomplete. Scalar fields on a
failed record are diagnostic observations and do not represent a decoded
configuration. Allocation failures follow the surrounding loader's normal
resource-limit handling.
Invalid enclave pointer values are handled within this same diagnostic
boundary: their pointer-field provenance and raw VA in the diagnostic survive
even when no valid normalized RVA exists.

CLI `inspect` prints the status, configuration fields, hexadecimal identities,
named known policy flags and match types, import names, and file provenance.
Import output is capped at 256 rows and control characters in names are
escaped. These records describe claimed enclave identity and policy; the
parser does not attest the enclave, authorize dependencies, enforce policy,
or create or execute an enclave.

Layouts follow Microsoft's
[IMAGE_ENCLAVE_CONFIG32](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_enclave_config32),
[IMAGE_ENCLAVE_CONFIG64](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_enclave_config64),
and [IMAGE_ENCLAVE_IMPORT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_enclave_import)
definitions and were cross-checked against Windows SDK 10.0.26100.0 `winnt.h`.
