#pragma once
#include "hexlab/loaders/loader.hpp"
#include "hexlab/loaders/x86_raw_profile.hpp"
#include "hexlab/loaders/arm_raw_profile.hpp"
#include <optional>
#include <stop_token>
namespace hexlab {
struct RawOptions {
    Architecture architecture;
    ExecutionMode mode;
    Address base;
    bool readable, writable, executable;
    std::optional<Address> entry;
    std::optional<X86RawProfile> x86_profile;
    std::optional<ArmRawProfile> arm_profile;
    ByteOrder order = ByteOrder::little;
};
HEXLAB_LOADERS_EXPORT Result<RawOptions> make_x86_raw_options(X86RawProfile);
HEXLAB_LOADERS_EXPORT Result<RawOptions> make_arm_raw_options(ArmRawProfile, std::stop_token = {});
// Validates context and coordinates without reading bytes. Extent and mapped
// entry checks are performed by load_raw when the storage size is available.
HEXLAB_LOADERS_EXPORT Result<bool> validate_raw_coordinates(const RawOptions &);
HEXLAB_LOADERS_EXPORT Result<std::shared_ptr<const Image>> load_raw(std::shared_ptr<const ByteStorage> storage,
                                                                    const RawOptions &options, std::stop_token stop);
} // namespace hexlab
