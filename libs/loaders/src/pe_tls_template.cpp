#include "hexlab/loaders/pe.hpp"
#include <limits>
#include <new>

namespace hexlab {
Result<std::vector<std::byte>> materialize_pe_tls_template(const LoadedImage &loaded,
                                                            std::uint64_t maximum_size) {
    if (!loaded.image)
        return Error{ErrorCode::invalid_argument, "PE TLS template requires a loaded image"};
    if (!loaded.metadata.pe || !loaded.metadata.pe->tls)
        return Error{ErrorCode::unsupported, "PE image has no parsed TLS directory"};
    const auto &tls = *loaded.metadata.pe->tls;
    if (tls.template_size > std::numeric_limits<std::uint64_t>::max() - tls.zero_fill)
        return Error{ErrorCode::overflow, "PE TLS template size overflows"};
    const auto total_size = tls.template_size + tls.zero_fill;
    if (total_size > maximum_size || total_size > std::numeric_limits<std::size_t>::max())
        return Error{ErrorCode::resource_limit, "PE TLS template exceeds materialization limit"};

    const auto runtime_base = loaded.load_base.value_or(loaded.metadata.preferred_base);
    if (tls.template_rva > std::numeric_limits<std::uint64_t>::max() - runtime_base)
        return Error{ErrorCode::overflow, "PE TLS template address overflows"};
    std::vector<std::byte> block;
    try {
        block.reserve(static_cast<std::size_t>(total_size));
        if (tls.template_size != 0) {
            if (tls.template_size > std::numeric_limits<std::size_t>::max())
                return Error{ErrorCode::resource_limit, "PE TLS source template exceeds host address space"};
            auto bytes = loaded.image->read(
                {loaded.image->layout().space.id, runtime_base + tls.template_rva},
                static_cast<std::size_t>(tls.template_size));
            if (!bytes) return bytes.error();
            block.insert(block.end(), bytes.value().begin(), bytes.value().end());
        }
        block.resize(static_cast<std::size_t>(total_size), std::byte{0});
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate PE TLS template"};
    }
    return block;
}
} // namespace hexlab
