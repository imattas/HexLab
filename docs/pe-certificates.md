# PE Security directory certificates

The PE Security data directory (index 4) is file-backed rather than RVA-based.
HexLab interprets its address field as a file offset, validates its 8-byte
offset and size alignment and full file extent, and applies a bounded record
count plus a 64 MiB aggregate table-size limit while walking
`WIN_CERTIFICATE` entries. The table may not overlap mapped headers or any
section's raw bytes. Each record must
contain the eight-byte header, declare a length of at least eight bytes, use
revision `0x0100` or `0x0200`, and have a nonzero certificate type. The record
length must fit the table; the next record begins at the checked 8-byte aligned
end. The table must be consumed exactly.

Metadata retains each header's length, revision, type, file source span, and
the raw certificate payload span. If a record or the table is malformed or
truncated, records successfully parsed before the failure remain available;
the table is marked incomplete and carries the parser diagnostic. The loader
also emits its normal PE directory warning and marks metadata partial. The desktop Certificates page shows those
fields and navigates to the payload bytes. Common X.509, PKCS#7, TS, and EFI
type values receive labels; other nonzero types remain opaque and visible. The
CLI prints the bounded record inventory, including revision, type, file offset,
declared length, completeness, and any parse diagnostic.

For each record, the inventory also retains the file span and size of its
0-to-7 alignment bytes and reports whether any are nonzero. This is a raw-byte
observation only: padding contents are not parsed, rejected, or treated as
evidence about signature validity or trust.

`compute_pe_authenticode_sha256` calculates SHA-256 and legacy SHA-1 image digests from the
original PE file bytes. It hashes the declared headers and initialized section
raw data in RVA order, excluding the optional-header checksum, the security
directory entry, and the certificate-table extent. It does not hash overlay
bytes beyond the last section. It rejects digest calculation if the certificate
table overlaps the declared headers or any section's raw bytes, so mapped image
content cannot be hidden inside an exclusion range. The CLI reports this digest
and byte count for loaded PE images.

`inspect_pe_authenticode_digest` accepts a selected PKCS#7 `WIN_CERTIFICATE`
and extracts either the SHA-1 or SHA-256 digest from the Authenticode
`SpcIndirectDataContent`. It validates the bounded DER envelope, content and
algorithm identifiers, and digest extent, then compares that value with the
corresponding image digest above. Other content types and digest algorithms report
unsupported; malformed or noncanonical DER reports an error. The result
includes both digest values, algorithm, match flag, and image byte count. The
CLI reports both image digest algorithms when no PKCS#7 record is available;
otherwise it reports the algorithm selected by the record's DigestInfo. SHA-1
support is for compatibility with legacy signed files and does not make that
digest collision resistant. CLI inspection reports the first PKCS#7
certificate's signed-content digest match
or mismatch alongside the image digest. This comparison does not verify the
CMS signer signature, certificate chain, timestamp, revocation, or publisher
trust. See Microsoft's [PE image-hash
description](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#appendix-a-calculating-authenticode-pe-image-hash).

`inspect_pe_authenticode_signers` separately inventories the bounded CMS
`SignerInfo` set from one PKCS#7 record. It reports each signer version,
issuer-and-serial or subject-key-identifier, digest and signature algorithm
OIDs, signed/unsigned attribute presence, and the signature byte extent with
file provenance. Issuer names remain encoded ASN.1 and are summarized by
length; serial numbers and key identifiers are shown as hex. The CLI displays
at most 32 signers. This is structural parsing only: attributes are validated
as bounded DER values; this inventory function does not verify signer
signatures or certificate trust. The separate Windows-only verification API
below checks cryptographic signatures.

`inspect_pe_authenticode_certificates` inventories embedded X.509 certificates
from the selected PKCS#7 SignedData certificate set. The result is capped at
1,024 certificates within the existing 64 MiB payload bound and includes each
certificate's file span, serial number, issuer and subject DER spans, raw
UTCTime/GeneralizedTime validity strings, and outer signature-algorithm OID.
Issuer and subject names remain navigable DER bytes rather than rendered or
normalized names. Non-X.509 CMS certificate choices are reported as
unsupported. This is certificate metadata only: dates are not evaluated,
certificate signatures and chains are not validated, revocation is not checked,
and no publisher identity or trust decision is made.

`verify_pe_authenticode_signatures` adds a Windows-only Crypt32 pass for each
CMS signer in the selected PKCS#7 record. It decodes the signed message and
asks Crypt32 to verify each indexed signer against certificates embedded in
that message. The API returns one result per signer; failed provider calls
retain the Win32 error code. On platforms without Crypt32 the API returns
unsupported. The CLI reports this status separately from the Authenticode
image-digest comparison above.

CMS signature validity means the signer public key verifies the signed CMS
content. It does not show that the embedded `SpcIndirectDataContent` digest
matches this PE image; use the digest-match status for that check. Neither
operation builds or validates a certificate chain, checks revocation or
timestamp validity, or establishes publisher trust. Crypt32's signed-message
decoding and signer verification follow Microsoft's [Decoding Signed
Data](https://learn.microsoft.com/en-us/windows/win32/seccrypto/decoding-signed-data)
and [`CryptMsgGetAndVerifySigner`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetandverifysigner)
documentation.

`verify_pe_authenticode_trust` adds a separate Windows-only trust result per
CMS signer. It first verifies the CMS signature, then asks Crypt32 to build a
certificate chain for the code-signing EKU and apply the Authenticode chain
policy against the host's current certificate stores. Embedded certificates
are supplied as the additional store; AIA and URL retrieval are disabled, so
this operation does not fetch certificates or revocation data. Results expose
signature validity, whether a chain was built, the chain trust flags, the
Authenticode policy error, and provider errors. `chain_trusted` is true only when
chain construction and policy validation both report no errors. The result
does not imply revocation or timestamp validation, and trust can differ across
machines as their local trust stores change. The CLI reports this separately
from the PE image digest match and raw CMS signature result. See Microsoft's
[`CertGetCertificateChain`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain)
and [`CertVerifyCertificateChainPolicy`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certverifycertificatechainpolicy)
documentation.

The desktop PE metadata pane exposes the same check on its Authenticode page.
Select a PKCS#7 row in Certificates and start verification; the UI displays
per-signer signature, chain, chain-status, policy, and provider results. The
check runs outside the UI thread, is bound to the immutable document snapshot,
and discards its result if the document changes before completion.

Invalid alignment, truncated records, unsupported
revisions, zero types, or out-of-file extents make PE metadata partial while
leaving the mapped image available.
