# HexLab third party dependencies

The analysis core and foundation tests use the C++ standard library. The desktop uses [wxWidgets](https://github.com/wxWidgets/wxWidgets) 3.2.12 at commit `3b7c7fc839093ad28146bd17555af2565c792c96`, corresponding to the peeled `v3.2.12` release tag. The source pin and its submodule pins are fixed in `cmake/WxWidgets.cmake` and upstream Git metadata.

wxWidgets uses the wxWindows Library Licence version 3.1. The full license is `docs/licence.txt` in its source checkout, with related terms in `docs/lgpl.txt` and `docs/gpl.txt`. Distribution includes these upstream notices unchanged. No application source license has been selected by the user.

The wxWidgets configuration builds shared libraries and enables native controls and AUI. Styled text, browser embedding and media controls are disabled for the foundation. Its bundled dependencies include PCRE2, zlib, libpng, Independent JPEG Group JPEG 9d, libtiff, Expat and NanoSVG. The application currently links the base, core and AUI libraries; unrelated wx libraries are excluded from the default build. Install the upstream notices for these dependencies alongside the application, including notices for bundled code compiled into wx libraries.

| Dependency | Upstream notice path inside wxWidgets source |
| --- | --- |
| PCRE2 | `3rdparty/pcre/LICENCE` |
| zlib | `src/zlib/LICENSE` |
| libpng | `src/png/LICENSE` |
| Independent JPEG Group JPEG 9d | `src/jpeg/README` |
| libtiff | `src/tiff/COPYRIGHT` |
| Expat | `src/expat/expat/COPYING` |
| NanoSVG | `3rdparty/nanosvg/LICENSE.txt` |

Optional build-time copies of upstream Catch are not linked to or used by HexLab's tests. The test harness is original and has no Catch dependency.

Segmented execution tests use pinned test-only QEMU, Bochs, NASM and firmware under `out/tools`. Provenance, hashes, upstream notices and execution limits are recorded in `tests/fixtures/x86_16_oracle` and the provisioning script. These tools are not linked into or shipped with the production runtime. `BUILD_TESTING=OFF` does not configure their tests.

Persistent-project work uses SQLite 3.54.1 as a separate shared runtime. The unmodified amalgamation is vendored in `third_party/sqlite`; its provenance records the official archive URL, publisher SHA3-256 and independently calculated SHA-256. Builds require no SQLite download. SQLite's dedication and provenance install under `share/hexlab/licenses/sqlite`. The build enables thread safety and omits dynamic extension loading. Database connections use bound values and the [official UTF-8 native-path interface](https://www.sqlite.org/c3ref/open.html).

FLIRT compressed `.sig` catalog bodies use the vendored miniz 3.1.2 zlib-compatible inflater. Only the static, inflate-only API is built into `hexlab_analysis`; no runtime DLL or network fetch is required. Upstream license, source hashes, and the local build configuration are recorded in `third_party/miniz/provenance.json`; the MIT notice is installed under `share/hexlab/licenses/miniz`.

The bounded EFI compression decoder adapts the decoder structure from TianoCore EDK II `BaseTools/Source/C/Common/Decompress.c`. It supports PI EFI compression type 1 with four position bits and the legacy Tiano type-2 variant with five position bits; type 2 is not a PI-defined compression value. The TianoCore BSD-2-Clause-Patent notice is retained in `libs/firmware/EDK2-LICENSE.txt` and installed under `share/hexlab/licenses/firmware`. The exact source, safety changes, and remaining opaque formats are documented in `docs/uefi-standard-compression.md`.

## Upstream code reuse

On 2026-10-21 the user explicitly authorized finding and incorporating existing projects/code. This supersedes earlier design notes requiring an entirely original engine. Reuse may include production decoders, lifters and decompiler components within the modular C++/wxWidgets application. No additional user approval is required for ordinary dependency integration within this scope.

For each actual import, retain its upstream license and copyright notices, record the exact commit or archive hash and any local changes, and install the required notices alongside shipped DLLs/resources. Check the imported files and their transitive dependencies as well as the top-level license. Keep upstream implementation details behind HexLab adapters so CLI, desktop and SDK consumers use the same typed facts and persistence rules. Decoder text alone is insufficient evidence for operand, flow, predication or source-state semantics.

Zydis 4.1.1 is vendored at upstream commit `a2278f1d254e492f6a6b39f6cb5d1f5d515659dc`; its required Zycore 1.5.2 source is pinned at `0b2432ced0884fd152b471d97ecf0258ff4d859f`. Both carry MIT notices at `third_party/zydis/LICENSE` and `third_party/zydis/dependencies/zycore/LICENSE`. The static decoder and Intel formatter are used as a conservative x86 fallback when HexLab's typed decoder reports an unsupported instruction. This fallback preserves bytes, length, display text and broad control-flow category; it deliberately does not claim operand or register semantics. The build compiles this dependency offline from the pinned vendored sources.

Initial candidates checked on 2026-10-21 are listed below. The Zydis candidate has since been imported as documented above. The remaining links are discovery references, not immutable dependency pins.

| Candidate | Potential use | Initial assessment |
| --- | --- | --- |
| [Zydis](https://github.com/zyantific/zydis) | Broader x86/x64 instruction decoding and encoding | [MIT license](https://github.com/zyantific/zydis/blob/v4.1.1/LICENSE). Integrated as a conservative decode/display fallback; its decoder text alone does not supply HexLab semantic facts. |
| [Capstone](https://github.com/capstone-engine/capstone) | Conservative decode/display fallback for ARM, Thumb, AArch64, MIPS32/64, PowerPC, RISC-V, MOS 6502 and x86 | [BSD 3-Clause license](https://github.com/capstone-engine/capstone/blob/5.0.9/LICENSE.TXT); pinned to commit `022575848782a4801fd150fdbc927effcbca0864` in `third_party/capstone`. Builds static-only with just these architecture engines enabled. Fallback instructions carry display text and byte length only; HexLab assigns no operands, flow, or register effects. |
| [RetDec](https://github.com/avast/retdec) | LLVM-based decompiler components | Main code uses [MIT](https://github.com/avast/retdec/blob/master/LICENSE), with separate [third-party terms](https://github.com/avast/retdec/blob/master/LICENSE-THIRD-PARTY). Assess individual components, LLVM compatibility and Windows build/runtime dependencies before choosing a scope. |
| [Remill](https://github.com/lifting-bits/remill) | Instruction semantics and lifting to LLVM bitcode | [Apache-2.0 license](https://github.com/lifting-bits/remill/blob/master/LICENSE). Its [README](https://github.com/lifting-bits/remill/blob/master/README.md) describes AArch32 support as underway and Windows support as experimental; assess those gaps before making it a required backend. |

These components do not by themselves establish source-bound mixed ARM/Thumb contexts, trustworthy relocation targets, project history or validated cache adoption. Those remain shared-engine integration requirements regardless of decoder choice.

Capstone 5.0.9 is vendored at upstream commit `022575848782a4801fd150fdbc927effcbca0864`. Its upstream `LICENSE.TXT` and `LICENSE_LLVM.TXT` are retained and installed under `share/hexlab/licenses/capstone`. HexLab uses the static library for unsupported instructions in enabled decoder contexts, including big-endian MIPS32/MIPS64 and PowerPC 32/64. The adapter is deliberately decode-only: it retains exact instruction length and formatted text in `Opcode::opaque`, leaves `FlowKind::fallthrough` as a placeholder, and gives no operand/register semantics. Reachability and function recovery stop at these opaque instructions. This prevents third-party formatting or groups from creating unverified control-flow edges. See `third_party/capstone/provenance.json` for the pin, enabled engines, and local integration details.
