# Binary patch workflow

Open the input as a project, navigate to the instruction or byte to change, and choose **Edit → Patch Bytes**. Enter replacement octets separated by spaces, such as `CC 90`. The replacement must cover initialized source bytes and keep the same length. Address patches are mapped back to canonical file offsets, so aliases in the image observe the same bytes. Firmware memory edits that require record regeneration must be applied to the corresponding source text instead.

The command stores an overlay on the embedded original input. It does not rewrite the original file. The listing and byte view show which ranges are patched, and analysis becomes stale until refreshed against the changed bytes. Each accepted patch is one durable project-history command. **Undo** restores the prior overlay; **Redo** reapplies it. Both remain available after closing and reopening the project, and a new edit after undo drops the redo branch.

Use **Edit → Review/Revert Patches** to inspect all currently changed ranges without navigating to each byte. The table shows file offset, range size, and the first 24 original and patched bytes; selecting a row shows the same preview and its size. The view lists at most 4096 normalized ranges. Read-only projects can review ranges but cannot revert them. **Revert selected range** writes that range's embedded original bytes through the regular patch command, so it becomes one durable history step and can itself be undone. A range with no changed bytes disappears from the manager after the project refreshes.

Choose **File → Export Patched Binary** to write the current effective bytes. Export streams the complete embedded input and overlay, checks the original input identity, publishes atomically, and reports the byte count and SHA-256 digest. It leaves the project and original input untouched, protects their paths and file aliases, and requires explicit replacement for an existing destination. For a CLI workflow:

```powershell
./hexlab_cli.exe project patch analysis.hxproj --at file:0x120 --bytes 'CC 90'
./hexlab_cli.exe project undo analysis.hxproj
./hexlab_cli.exe project redo analysis.hxproj
./hexlab_cli.exe project export analysis.hxproj --output patched.bin
Get-FileHash patched.bin -Algorithm SHA256
```

Compare the reported digest with `Get-FileHash` to verify the published file. PE checksums and cryptographic signatures are not rebuilt; edits can invalidate them. Export preserves the exact patched bytes even when a header edit makes the image unavailable for analysis.
