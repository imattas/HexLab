#pragma once
#include "hexlab/analysis/elf_relocations.hpp"
#include "hexlab/analysis/macho_relocations.hpp"
#include "hexlab/analysis/macho_dyld.hpp"
#include <variant>
namespace hexlab {
enum class RelocationFormat { elf, macho };
struct OperandResolution {
    std::optional<Address> address;
    std::optional<std::uint64_t> constant;
    std::vector<std::uint64_t> relocations;
    std::variant<ElfResolutionReason, MachOResolutionReason> reason = ElfResolutionReason::none;
    std::optional<MachODyldOperand> dyld;
    bool relocated() const noexcept { return !relocations.empty() || dyld.has_value(); }
};
// Shared format dispatch. The underlying resolvers retain their own namespaces,
// equations and typed reasons, and borrow the supplied immutable metadata.
class RelocationResolver {
  public:
    HEXLAB_ANALYSIS_EXPORT static Result<RelocationResolver> create(const ImageMetadata &, std::stop_token);
    HEXLAB_ANALYSIS_EXPORT static Result<RelocationResolver> create(const Image &, const ImageMetadata &,
                                                                    std::stop_token);
    HEXLAB_ANALYSIS_EXPORT Result<bool> code_start(Address, std::stop_token) const;
    HEXLAB_ANALYSIS_EXPORT Result<std::optional<MachODyldOperand>> instruction_fixup(const Instruction &,
                                                                                     std::stop_token) const;
    HEXLAB_ANALYSIS_EXPORT std::optional<Address> preferred_header() const noexcept;
    HEXLAB_ANALYSIS_EXPORT Result<OperandResolution> operand(const Instruction &, std::uint32_t, std::stop_token) const;
    HEXLAB_ANALYSIS_EXPORT Result<OperandResolution> data(std::uint64_t, std::stop_token) const;
    // Resolve a data slot at an image address when one exact relocation or
    // dyld rebase owns the complete field. Unassociated bytes are left opaque.
    HEXLAB_ANALYSIS_EXPORT Result<OperandResolution> data_at(const Image &, Address, std::uint8_t,
                                                              std::stop_token) const;
    HEXLAB_ANALYSIS_EXPORT Result<std::optional<Address>> control_target(const Image &, const Instruction &,
                                                                         std::stop_token) const;
    HEXLAB_ANALYSIS_EXPORT const ElfSymbol *elf_symbol(std::uint64_t) const noexcept;
    HEXLAB_ANALYSIS_EXPORT const MachOSymbol *macho_symbol(std::uint64_t) const noexcept;
    // Borrowed metadata supplied with the source-image overload, when available.
    const ImageMetadata *source_metadata() const noexcept { return source_metadata_; }
    RelocationFormat format() const noexcept {
        return std::holds_alternative<MachORelocationResolver>(value_) ? RelocationFormat::macho
                                                                       : RelocationFormat::elf;
    }

  private:
    using Resolver = std::variant<ElfRelocationResolver, MachORelocationResolver>;
    Resolver value_;
    std::optional<MachODyldResolver> dyld_;
    const Image *source_image_ = nullptr;
    const MachOMetadata *source_macho_ = nullptr;
    const ImageMetadata *source_metadata_ = nullptr;
    static Result<RelocationResolver> create_base(const ImageMetadata &, std::stop_token);
    explicit RelocationResolver(Resolver value) : value_(std::move(value)) {}
};
} // namespace hexlab
