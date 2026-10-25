# Desktop byte patching

The Bytes pane exposes **Patch bytes...** for a selected byte in a writable project. The dialog starts with the current eight bytes and shows the current and replacement bytes before applying the edit. Enter one to 256 hexadecimal octets, for example `90 90 C3`.

The selected range must stay inside initialized file-backed bytes. Virtual-address edits are checked byte by byte for contiguous addresses in the same address space and contiguous file offsets. Raw-file offsets remain available for bytes that do not have a mapped virtual address. Zero-fill, holes, and ranges that cross a file mapping gap are rejected before submission.

Applying a patch submits the existing persistent `PatchBytes` project command. It creates one undoable history step and advances the byte revision; dependent analysis becomes stale and is refreshed against the changed bytes. The original input file is unchanged. Use **Export Patched Binary...** to publish a patched copy. Binary export does not rebuild PE checksums or cryptographic signatures.

The Bytes pane limits each interactive patch to 256 bytes. Larger patch spans remain available through the project command API, which has its own 16 MiB bound and mapping validation.
