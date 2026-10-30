# PE section profile

`analyze_pe_sections` reports each PE section's declared raw and virtual sizes, RVA, permission bits, and Shannon entropy over the file-backed raw extent. It reads raw bytes in 64 KiB chunks, validates each extent against the input, and supports cancellation between chunks. A zero-length raw section has entropy 0.

The CLI's normal PE description prints this profile. Entropy is a heuristic: a high value can indicate compressed, encrypted, or otherwise byte-diverse data, but does not establish packing or malicious behavior. Permission bits report section declarations and do not prove the final runtime page protections. The profile does not inspect overlay data or virtual zero-fill bytes.
