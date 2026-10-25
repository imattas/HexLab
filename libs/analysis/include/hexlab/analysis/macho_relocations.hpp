#pragma once
#include "hexlab/analysis/analysis.hpp"
#include <memory>
namespace hexlab {
enum class MachOResolutionReason {
    none,
    resolved,
    ambiguous,
    field_mismatch,
    unsupported,
    unavailable_symbol,
    undefined_symbol,
    symbol_not_address,
    weak_symbol,
    unavailable_field,
    overflow,
    different_domains,
    retained,
    runtime_binding
};
struct MachOOperandResolution {
    MachOResolutionReason reason = MachOResolutionReason::none;
    std::optional<Address> address;
    // A difference or absolute scalar is not evidence of a pointer.
    std::optional<std::uint64_t> constant;
    // Authoritative metadata row indexes, including compound companions.
    std::vector<std::uint64_t> relocations;
    bool relocated() const noexcept { return !relocations.empty(); }
};
struct MachOResolutionLimits {
    std::uint64_t lookup_work = 64 * 1024 * 1024;
    std::uint32_t max_matches = 4096;
};
// Borrows immutable metadata. Retain it unchanged for the resolver lifetime.
// Construct once per analysis; copies share the bounded lookup index.
class MachORelocationResolver {
  public:
    HEXLAB_ANALYSIS_EXPORT static Result<MachORelocationResolver> create(const ImageMetadata &, std::stop_token);
    HEXLAB_ANALYSIS_EXPORT static Result<MachORelocationResolver> create(const ImageMetadata &, MachOResolutionLimits,
                                                                         std::stop_token);
    HEXLAB_ANALYSIS_EXPORT Result<MachOOperandResolution> operand(const Instruction &, std::uint32_t,
                                                                  std::stop_token) const;
    HEXLAB_ANALYSIS_EXPORT Result<MachOOperandResolution> data(std::uint64_t, std::stop_token) const;
    HEXLAB_ANALYSIS_EXPORT Result<MachOOperandResolution> data_at(Address, std::optional<FileOffset>, std::uint8_t,
                                                                  std::stop_token) const;
    HEXLAB_ANALYSIS_EXPORT const MachOSymbol *symbol(std::uint64_t) const noexcept;
    HEXLAB_ANALYSIS_EXPORT Result<std::optional<Address>> control_target(const Image &, const Instruction &,
                                                                         std::stop_token) const;

  private:
    struct State;
    std::shared_ptr<const State> state_;
    explicit MachORelocationResolver(std::shared_ptr<const State> state) : state_(std::move(state)) {}
};
} // namespace hexlab
