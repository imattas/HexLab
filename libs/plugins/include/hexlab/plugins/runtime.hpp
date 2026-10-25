#pragma once

#include "hexlab/loaders/loader.hpp"
#include "hexlab/plugins/plugins.hpp"
#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/instruction.hpp"

#include <variant>

namespace hexlab::plugins {

// Semantic extension records become validated core IR instructions. Legacy
// ABI 1.3 records remain display-only and opaque.
using DecodeDispatchResult = std::variant<DecodeResult, ProcessorDecodeResult, Instruction>;
using LoaderDispatchResult = std::variant<DetectedFormat, LoaderProbeResult>;

// Semantic extensions get first refusal, followed by legacy display decoders,
// then the built-in implementation. Malformed records surface as errors.
HEXLAB_PLUGINS_EXPORT Result<DecodeDispatchResult> decode_with_extensions(
    const PluginManager&, DecodeContext, std::span<const std::byte>, Address);
// Applies only display metadata to a core-decoded NOP. Extension operands and
// control flow are intentionally not imported into semantic IR.
HEXLAB_PLUGINS_EXPORT Status apply_display_extension(const PluginManager&, Instruction&);
// Explicit semantic-IR path. The snapshot must carry a key produced using
// manager.analysis_options with the same analysis budget values supplied here.
// Stale/unkeyed snapshots fail; load/unload/quarantine invalidates the result.
// At most 4096 plugin instruction programs are requested per function.
HEXLAB_PLUGINS_EXPORT Result<decompiler::LiftedFunction> lift_function_with_extensions(
    const PluginManager &, const FunctionRecord &, const FunctionSnapshot &,
    const AnalysisOptions &analysis_options = {}, std::stop_token = {});
HEXLAB_PLUGINS_EXPORT Result<LoaderDispatchResult> detect_with_extensions(
    const PluginManager&, const ByteStorage&, std::span<const std::uint8_t> probe_prefix,
    const std::string& requested_format = {});

} // namespace hexlab::plugins
