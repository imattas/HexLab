#pragma once
#include "hexlab/firmware/firmware.hpp"
#include "hexlab/loaders/loaded_image.hpp"
#include <stop_token>
#include <string_view>

namespace hexlab {
struct FirmwareLoadOptions {
    firmware::Format format = firmware::Format::intel_hex;
    Architecture architecture = Architecture::unknown;
    ExecutionMode mode = ExecutionMode::unknown;
    bool executable = false;
    firmware::ParseOptions parse_options{};
};
// Firmware records are packed into immutable backing storage while each
// segment retains its sparse target address. Metadata keeps original line and
// record identity so tools can trace mapped bytes to source records.
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_firmware(std::string_view text,
    const FirmwareLoadOptions &, std::stop_token stop = {});
} // namespace hexlab
