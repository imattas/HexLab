#pragma once
#include "hexlab/loaders/loaded_image.hpp"
#include <cstdint>
#include <memory>
#include <stop_token>
#include <vector>

namespace hexlab {
struct DexMetadataUsage {
    std::uint64_t rows = 0, string_capacity = 0, retained_capacity_bytes = 0, class_member_rows = 0;
};
// Bounded standard DEX reader. Defined Dalvik code items are mapped into
// method-relative address spaces so branch offsets remain local to a method.
// Loaded metadata retains class definitions and their declared members as
// identifier-table indexes with raw access flags, plus complete source-backed
// string/field/method identifier catalogs. These references are not resolved
// against external classes or imported into shared symbols or types.
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_dex(std::shared_ptr<const ByteStorage>, std::stop_token);
// Loads and validates each sequential DEX 041 logical member independently.
// The member images retain the shared physical container as their byte source.
// The physical source and cumulative logical member extents are capped at
// 512 MiB; loading is capped at 256 members, one million identifier rows,
// two million mapped/decoded metadata rows, 64 MiB of decoded string capacity,
// 256 MiB of DexMetadata vector/string capacity, and one million class,
// interface, and declared-member rows across the whole container.
HEXLAB_LOADERS_EXPORT Result<std::vector<LoadedImage>>
load_dex041_container(std::shared_ptr<const ByteStorage>, std::stop_token);
// Measures bounded retained vector/string usage for cross-container budgets.
HEXLAB_LOADERS_EXPORT DexMetadataUsage measure_dex_metadata_usage(const DexMetadata &, std::stop_token = {});
}
