#pragma once
#include "hexlab/analysis/analysis.hpp"
#include <memory>
namespace hexlab {
enum class MachODyldSource { classic, chained };
struct MachODyldIdentity {
    MachODyldSource source = MachODyldSource::classic;
    std::uint64_t row = 0;
    auto operator<=>(const MachODyldIdentity &) const = default;
};
enum class MachODyldResolutionReason {
    none,
    resolved,
    runtime_binding,
    ambiguous,
    field_mismatch,
    unsupported,
    unavailable_field,
    overflow,
    non_pointer,
    authenticated,
    missing_anchor,
    unmapped_target
};
struct MachODyldBinding {
    std::optional<std::int32_t> library_ordinal;
    std::string name;
    std::int64_t addend = 0;
    bool weak_import = false;
    // Present only for the original packed chained-import namespace.
    std::optional<std::uint64_t> import_row;
    bool operator==(const MachODyldBinding &) const = default;
};
struct MachODyldResolution {
    MachODyldResolutionReason reason = MachODyldResolutionReason::none;
    std::optional<Address> address;
    std::optional<std::uint64_t> constant;
    std::optional<MachODyldBinding> binding;
    std::vector<MachODyldIdentity> origins;
    bool associated() const noexcept { return !origins.empty(); }
    bool operator==(const MachODyldResolution &) const = default;
};
struct MachODyldResolutionLimits {
    std::uint64_t lookup_work = 64 * 1024 * 1024;
    std::uint32_t max_matches = 4096;
};
enum class MachODyldUse { raw_data, encoded_field, memory_slot, instruction_bytes };
struct MachODyldQuery {
    Address at{};
    std::uint8_t width = 0;
    // Relative instruction span; an operand field for encoded_field, or an
    // affected instruction window for instruction_bytes. Absent for slot reads.
    std::optional<EncodedField> field;
    bool operator==(const MachODyldQuery &) const = default;
};
struct MachODyldOperand {
    MachODyldUse use = MachODyldUse::encoded_field;
    MachODyldResolution resolution;
    std::vector<MachODyldQuery> queries;
};
// Borrows the immutable image and metadata. Slot addresses are storage locations,
// not callees; only a resolved result supplies a preferred-space pointer value.
// No library loading, slide, process memory, PAC or source mutation is involved.
class MachODyldResolver {
  public:
    HEXLAB_ANALYSIS_EXPORT static Result<MachODyldResolver> create(const Image &, const ImageMetadata &,
                                                                   std::stop_token);
    HEXLAB_ANALYSIS_EXPORT static Result<MachODyldResolver> create(const Image &, const ImageMetadata &,
                                                                   MachODyldResolutionLimits, std::stop_token);
    HEXLAB_ANALYSIS_EXPORT Result<MachODyldResolution> slot(Address, std::uint8_t width, std::stop_token) const;
    HEXLAB_ANALYSIS_EXPORT Result<MachODyldResolution> data(MachODyldIdentity, std::stop_token) const;
    HEXLAB_ANALYSIS_EXPORT std::optional<Address> preferred_header() const noexcept;

  private:
    struct State;
    std::shared_ptr<const State> state_;
    explicit MachODyldResolver(std::shared_ptr<const State> state) : state_(std::move(state)) {}
};
} // namespace hexlab
