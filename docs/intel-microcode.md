# Intel microcode update inventory

Inspect one update at a caller-selected file offset:

```text
hexlab_cli firmware inspect firmware.bin --microcode-offset 0x2000 --format intel-microcode
```

The parser reads the 48-byte Intel update header, applies the legacy size
defaults (2000 data bytes and 2048 total bytes when the corresponding header
fields are zero), and bounds the selected update to the supplied input. It
reports revision, raw date, processor signature/flags, loader revision, size
and reserved-field facts. It checks the DWORD checksum over header plus update
data, the optional extension-table checksum, and each extended signature's
compensating checksum. Every extended signature includes its file offset.

The payload is encrypted and treated as opaque. The parser does not discover
FIT entries or microcode offsets, map a processor to a matching update, verify
cryptographic authenticity, extract data, or load microcode. Input is limited
to 512 MiB, one update to 16 MiB, and extension signatures to one million;
CLI output displays at most 4096 signature rows. Format rules follow the
[Intel SDM, Volume 3A](https://cdrdv2-public.intel.com/835754/253668-sdm-vol-3a.pdf)
and Linux's [Intel microcode sanity checks](https://github.com/torvalds/linux/blob/master/arch/x86/kernel/cpu/microcode/intel.c).
