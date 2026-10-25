# Segmented x86 raw profiles

HexLab supports a bounded original scalar decoder for 386 real and protected environments, with code domains using 16-bit or 32-bit defaults. A profile declares static mappings; HexLab does not execute the input or infer runtime segment registers.

Use `--format raw --profile mapping.profile` with `disassemble` or `project create`. Profile intent replaces flat `--arch`, `--base` and `--entry` arguments. Desktop raw import offers the same profile option. Parsing happens on the worker. Projects embed the canonical profile and original bytes, so they reopen after the external files disappear.

```text
hexlab-x86-profile 1
environment real386
a20 enabled
load 0x10010
entry 7 0x10
stack none
domains 2
domain 7 0x1000 code "text" real
domain 2 0x1001 data "alias" real
```

Domain IDs differ from selectors. Here `1000:0010` and `1001:0000` share the first input byte. Annotations retain domain identity; patches modify shared canonical bytes. Byte searches report a file coordinate when reverse mapping is ambiguous. Immediate searches retain the known instruction domain.

```powershell
hexlab_cli project create sample.hxproj --input sample.bin --format raw --profile mapping.profile
hexlab_cli project rename sample.hxproj --at seg:1000:0010 --name entry_point
hexlab_cli project patch sample.hxproj --at seg:1001:0000 --bytes '90'
hexlab_cli project export sample.hxproj --output patched.bin
```

Profile numbers accept decimal or `0x` hexadecimal. CLI `seg:<selector>:<offset>` and native selector jumps use hexadecimal, with optional `0x` prefixes.

This protected-mode example declares code16 and an independent stack32 descriptor:

```text
hexlab-x86-profile 1
environment protected386
a20 enabled
load 0x10000
entry 7 0
stack 0x10
domains 2
domain 7 8 code "code16" ffff0000019a0000
domain 2 0x10 data "stack32" ffff000002924000
```

Descriptors contain exactly eight little-endian bytes. Code defaults, operand/address overrides and stack address width remain separate. Input need not contain stack bytes. Real-mode load positions are physical; protected-mode positions are linear. Only initialized intersections map to file bytes; absent memory is not filled with zeros. Logical bounds are checked before A20 translation.

The UTF-8 codec accepts BOM, CRLF, comments beginning with `#`, and quoted names with escaped backslashes and quotes. Bounds are 1 MiB, 4096 domains and 256 bytes per name. Unknown or duplicate fields and unbacked entry points are rejected. Import mappings are immutable; persistent mapping edits remain future work.

Direct far targets resolve only for declared real mappings or supported same-privilege nonconforming protected code. Gates, privilege transitions, conforming targets and indirect runtime state remain unresolved. Unknown DS/SS values are not inferred. Ordinary code16 fallthrough preserves 386 EIP behavior; CALL16 stores a 16-bit return offset. Exact 8086/286, virtual-8086, unreal mode, paging, full privilege semantics and full ISA coverage are outside this stage.
