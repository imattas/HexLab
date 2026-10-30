#include "hexlab/image/external_inputs.hpp"
#include "hexlab/core/encoding.hpp"
#include <algorithm>
#include <string_view>

namespace hexlab {
Result<ExternalInputManifest> fingerprint_external_inputs(
    std::span<const ExternalAnalysisInput> inputs, const ExternalInputLimits &limits, std::stop_token stop) {
    try {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "External input fingerprinting canceled"};
        if (inputs.size() > limits.inputs)
            return Error{ErrorCode::resource_limit, "External input manifest exceeds its source limit"};
        std::vector<const ExternalAnalysisInput *> ordered;
        std::size_t identity_bytes = 0;
        for (const auto &input : inputs) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "External input fingerprinting canceled"};
            if (!input.storage || input.identity.empty())
                return Error{ErrorCode::invalid_argument, "External input requires storage and a nonempty identity"};
            if (input.identity.size() > 4096 || input.identity.size() > limits.identity_bytes - identity_bytes)
                return Error{ErrorCode::resource_limit, "External input identities exceed their byte limit"};
            identity_bytes += input.identity.size();
            ordered.push_back(&input);
        }
        std::sort(ordered.begin(), ordered.end(), [](const auto *left, const auto *right) {
            return left->identity < right->identity;
        });
        ExternalInputManifest manifest;
        Sha256 aggregate;
        constexpr std::string_view domain = "HexLab/external-byte-manifest/v1";
        auto appended = aggregate.update(std::as_bytes(std::span(domain.data(), domain.size())));
        if (!appended) return appended.error();
        appended = aggregate.update(encode_u64(ordered.size()));
        if (!appended) return appended.error();
        for (const auto *input : ordered) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "External input fingerprinting canceled"};
            if (!manifest.dependencies.empty() && manifest.dependencies.back().identity == input->identity)
                return Error{ErrorCode::conflict, "External input identities must be unique"};
            const auto size = input->storage->size();
            if (size > limits.total_bytes - manifest.total_bytes)
                return Error{ErrorCode::resource_limit, "External inputs exceed their total byte limit"};
            manifest.total_bytes += size;
            Sha256 content;
            for (std::uint64_t offset = 0; offset < size;) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "External input fingerprinting canceled"};
                const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(65536, size - offset));
                auto view = input->storage->read_at({offset}, count);
                if (!view) return view.error();
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "External input fingerprinting canceled"};
                if (view.value().bytes.size() != count)
                    return Error{ErrorCode::io, "External input returned an incomplete fingerprint read"};
                appended = content.update(view.value().bytes);
                if (!appended) return appended.error();
                offset += count;
            }
            if (input->storage->size() != size)
                return Error{ErrorCode::conflict, "External input size changed while fingerprinting"};
            manifest.dependencies.push_back({input->identity, size, content.digest()});
            appended = aggregate.update(encode_u64(input->identity.size()));
            if (!appended) return appended.error();
            appended = aggregate.update(std::as_bytes(std::span(input->identity.data(), input->identity.size())));
            if (!appended) return appended.error();
            appended = aggregate.update(encode_u64(size));
            if (!appended) return appended.error();
            appended = aggregate.update(manifest.dependencies.back().sha256);
            if (!appended) return appended.error();
        }
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "External input fingerprinting canceled"};
        manifest.fingerprint = aggregate.digest();
        return manifest;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate external input manifest"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "External input manifest exceeds host limits"};
    }
}
}
