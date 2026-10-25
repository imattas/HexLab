#pragma once
#include "hexlab/image/image.hpp"
#include "hexlab/loaders/loaders_export.hpp"
namespace hexlab {
enum class Format { automatic, raw, pe, elf, macho, ar, intel_hex, s_record, plugin, wasm, dex, jvm, minidump };
enum class DetectedFormat { unknown, pe_candidate, elf_candidate, macho_candidate, ar_candidate, wasm_candidate, dex_candidate, jvm_candidate, minidump_candidate };
HEXLAB_LOADERS_EXPORT Result<DetectedFormat> detect_format(const ByteStorage &storage);
} // namespace hexlab
