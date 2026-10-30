#pragma once
#include "hexlab/image/byte_storage.hpp"
#include <string>
#include <vector>

namespace hexlab {
// Stable caller-owned names identify all immutable byte inputs used by a
// resolver. Callback code/configuration still needs its own stable identity.
struct ExternalAnalysisInput {
    std::string identity;
    std::shared_ptr<const ByteStorage> storage;
};
struct ExternalInputDependency {
    std::string identity;
    std::uint64_t size = 0;
    Sha256Digest sha256{};
    bool operator==(const ExternalInputDependency &) const = default;
};
struct ExternalInputManifest {
    Sha256Digest fingerprint{};
    std::vector<ExternalInputDependency> dependencies;
    std::uint64_t total_bytes = 0;
};
struct ExternalInputLimits {
    std::size_t inputs = 4096, identity_bytes = 1024 * 1024;
    std::uint64_t total_bytes = 64 * 1024 * 1024;
};
// Hashes every byte of every declared input in bounded chunks. Names must be
// nonempty and unique. Sorting makes the manifest independent of input order;
// names, sizes and full content digests are domain-separated and length-coded.
HEXLAB_IMAGE_EXPORT Result<ExternalInputManifest> fingerprint_external_inputs(
    std::span<const ExternalAnalysisInput>, const ExternalInputLimits & = {}, std::stop_token = {});
}
