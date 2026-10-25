#pragma once
#include "hexlab/analysis/analysis.hpp"
#include <memory>
namespace hexlab {
enum class ElfResolutionReason {
    none,
    resolved,
    ambiguous,
    field_mismatch,
    unsupported,
    unavailable_symbol,
    undefined_symbol,
    symbol_not_address,
    preemptible_symbol,
    unavailable_addend,
    overflow
};
struct ElfOperandResolution {
    ElfResolutionReason reason = ElfResolutionReason::none;
    std::optional<Address> address;
    // Indexes into the authoritative ElfMetadata::relocations, in canonical order.
    std::vector<std::uint64_t> relocations;
    bool relocated() const noexcept { return !relocations.empty(); }
};
struct ElfResolutionLimits {
    std::uint64_t lookup_work = 64 * 1024 * 1024;
    std::uint32_t max_matches = 4096;
};
// Borrows immutable metadata. Retain it unchanged for the resolver's lifetime.
// Construct once per analysis; interval and symbol indexes are shared by copies.
class ElfRelocationResolver {
  public:
    HEXLAB_ANALYSIS_EXPORT static Result<ElfRelocationResolver> create(const ImageMetadata &, std::stop_token);
    HEXLAB_ANALYSIS_EXPORT static Result<ElfRelocationResolver> create(const ImageMetadata &, ElfResolutionLimits,
                                                                       std::stop_token);
    HEXLAB_ANALYSIS_EXPORT Result<ElfOperandResolution> operand(const Instruction &, std::uint32_t,
                                                                std::stop_token) const;
    // Declared symbol-plus-addend association for a raw relocation field; this
    // neither applies linker bytes nor dereferences a runtime pointer.
    HEXLAB_ANALYSIS_EXPORT Result<ElfOperandResolution> data(std::uint64_t, std::stop_token) const;
    HEXLAB_ANALYSIS_EXPORT Result<ElfOperandResolution> data_at(Address, std::optional<FileOffset>, std::uint8_t,
                                                                std::stop_token) const;
    // Borrowed from the same immutable metadata; unavailable bounds return null.
    HEXLAB_ANALYSIS_EXPORT const ElfSymbol *symbol(std::uint64_t) const noexcept;
    HEXLAB_ANALYSIS_EXPORT Result<std::optional<Address>> control_target(const Image &, const Instruction &,
                                                                         std::stop_token) const;

  private:
    struct State;
    std::shared_ptr<const State> state_;
    explicit ElfRelocationResolver(std::shared_ptr<const State> state) : state_(std::move(state)) {}
};
// Convenience for individual queries, including a manually decoded listing row.
HEXLAB_ANALYSIS_EXPORT Result<std::optional<Address>> resolve_control_target(const Image &, const ImageMetadata &,
                                                                             const Instruction &, std::stop_token);
} // namespace hexlab
