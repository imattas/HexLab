# LZMA SDK decoder provenance and notice

HexLab vendors `LzmaDec.c`, `LzmaDec.h`, `7zTypes.h`, `Precomp.h`, `Bra86.c`, and
`Bra.h` from
TianoCore EDK II `MdeModulePkg/Library/LzmaCustomDecompressLib/Sdk/C`.
The source file headers state that Igor Pavlov's LZMA SDK code is in the
public domain. EDK II's library metadata identifies the imported SDK as LZMA SDK
19.00, placed in the public domain on 2019-02-21. The Intel EDK II wrapper
sources are not vendored; their applicable BSD-2-Clause-Patent notice is
retained at `libs/firmware/EDK2-LICENSE.txt`.

Upstream revision: `1436aea4d5707e672672a11bda72be2c63c936c3`.

Upstream sources:

- https://github.com/tianocore/edk2/tree/1436aea4d5707e672672a11bda72be2c63c936c3/MdeModulePkg/Library/LzmaCustomDecompressLib/Sdk/C
- https://github.com/tianocore/edk2/blob/1436aea4d5707e672672a11bda72be2c63c936c3/MdeModulePkg/Library/LzmaCustomDecompressLib/LzmaCustomDecompressLib.inf
