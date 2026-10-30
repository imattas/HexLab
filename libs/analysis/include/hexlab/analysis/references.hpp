#pragma once
#include "hexlab/analysis/functions.hpp"
#include "hexlab/analysis/elf_relocations.hpp"
#include "hexlab/analysis/macho_relocations.hpp"
#include "hexlab/analysis/macho_dyld.hpp"
#include "hexlab/core/paging.hpp"
#include <tuple>
#include <vector>
namespace hexlab {
class Image;
struct ReferenceId {
    std::uint64_t value;
    auto operator<=>(const ReferenceId &) const = default;
};
enum class ReferenceKind {
    call,
    jump,
    conditional_jump,
    memory_read,
    memory_write,
    memory_read_write,
    memory_address,
    imported_call,
    imported_jump,
    user_code,
    user_data,
    relocation,
    dyld_fixup
};
enum class UnresolvedReason {
    register_value,
    memory_address,
    memory_value,
    relative_overflow,
    missing_operand,
    ambiguous_import,
    far_selector,
    elf_relocation,
    macho_relocation,
    macho_dyld
};
using ReferenceExpression =
    std::variant<std::monostate, RegisterOperand, MemoryOperand, RelativeOperand, FarPointerOperand, FarMemoryOperand,
                 ArmMemoryOperand, ThumbRelativeOperand>;
struct UnresolvedTarget {
    UnresolvedReason reason;
    ReferenceExpression expression;
};
using ReferenceTarget = std::variant<Location, ExternalIdentity, UnresolvedTarget>;
struct ElfSymbolIdentity {
    ElfTableSource table;
    std::uint32_t index = 0;
    bool operator==(const ElfSymbolIdentity &) const = default;
};
struct ElfReferenceOrigin {
    ElfRelocation relocation;
    std::optional<ElfSymbol> symbol;
    bool operator==(const ElfReferenceOrigin &) const = default;
};
struct ElfReferenceProvenance {
    ElfResolutionReason resolution;
    std::vector<ElfReferenceOrigin> origins;
    bool operator==(const ElfReferenceProvenance &) const = default;
};
struct ElfVTableReferenceProvenance {
    Address table_begin;
    Address address_point;
    Address type_info;
    Address slot;
    std::uint32_t slot_index = 0;
    std::uint32_t symbol_index = 0;
    std::optional<std::string> type_name;
    bool operator==(const ElfVTableReferenceProvenance &) const = default;
};
struct MachOSymbolIdentity {
    std::uint32_t slice_index = 0;
    FileOffset slice_offset{};
    std::uint32_t table_command = 0;
    FileOffset table_offset{};
    std::uint32_t index = 0;
    bool operator==(const MachOSymbolIdentity &) const = default;
};
struct MachOReferenceContext {
    std::uint32_t slice_index = 0;
    std::uint64_t slice_offset = 0, slice_size = 0;
    std::uint32_t cpu_type = 0, cpu_subtype = 0, file_type = 0, flags = 0;
    bool is_64 = false;
    ByteOrder order = ByteOrder::little;
    bool operator==(const MachOReferenceContext &) const = default;
};
struct MachOReferenceOrigin {
    MachORelocation relocation;
    MachORelocationTable table;
    std::optional<MachOSymbolTable> symbol_table;
    std::optional<MachOSymbol> symbol;
    bool operator==(const MachOReferenceOrigin &) const = default;
};
struct MachOReferenceProvenance {
    MachOResolutionReason resolution = MachOResolutionReason::none;
    MachOReferenceContext context;
    std::optional<std::uint64_t> constant;
    std::vector<MachOReferenceOrigin> origins;
    bool operator==(const MachOReferenceProvenance &) const = default;
};
struct MachODyldClassicOrigin {
    MachODyldOperation operation;
    MachODyldFixup fixup;
    bool operator==(const MachODyldClassicOrigin &) const = default;
};
struct MachODyldChainedOrigin {
    MachOChainedHeader header;
    MachOChainedPointer pointer;
    std::optional<MachOChainedImport> import;
    // Fixed start-record context, without duplicating its whole page array for
    // every pointer word. Pointer page/start indexes retain their original roles.
    std::uint64_t starts_record_file_offset = 0, segment_offset = 0;
    std::uint32_t segment_index = 0, max_valid_pointer = 0;
    std::uint16_t pointer_format = 0;
    bool starts_complete = true;
    bool operator==(const MachODyldChainedOrigin &) const = default;
};
struct MachODyldReferenceOrigin {
    MachODyldIdentity identity;
    std::uint32_t stream_index = 0;
    MachODyldStream stream;
    std::variant<MachODyldClassicOrigin, MachODyldChainedOrigin> record;
    bool operator==(const MachODyldReferenceOrigin &) const = default;
};
struct MachODyldReferenceProvenance {
    MachOReferenceContext context;
    std::optional<Address> header_anchor;
    MachODyldResolution resolution;
    std::vector<MachODyldReferenceOrigin> origins;
    MachODyldUse use = MachODyldUse::raw_data;
    std::vector<MachODyldQuery> queries;
    bool operator==(const MachODyldReferenceProvenance &) const = default;
};
// An edge means consumer_instruction_id used a value produced by
// producer_instruction_id while deriving the reference target.
struct ReferenceProducerDependency {
    std::uint64_t consumer_instruction_id = 0, producer_instruction_id = 0;
    bool operator==(const ReferenceProducerDependency &) const = default;
};
struct ReferenceProducerImmediate {
    std::uint64_t instruction_id = 0;
    std::uint32_t operand_index = 0;
    std::uint64_t value = 0;
    std::uint16_t encoded_width = 0, effective_width = 0;
    bool is_signed = false;
    bool operator==(const ReferenceProducerImmediate &) const = default;
};
struct ReferenceProducerGraph {
    std::vector<ReferenceProducerDependency> dependencies;
    // Immediate constants retained from instructions in this causal chain.
    std::vector<ReferenceProducerImmediate> immediates;
    bool truncated = false, ambiguous = false, cycle = false;
    bool operator==(const ReferenceProducerGraph &) const = default;
};
enum class ReferenceProvenanceKind {
    decoded,
    import_slot,
    user,
    elf_relocation,
    macho_relocation,
    macho_dyld,
    dataflow,
    elf_vtable_slot
};
struct ReferenceProvenance {
    ReferenceProvenanceKind kind;
    std::uint64_t instruction_id = 0, user_id = 0;
    // Bounded instruction IDs that contributed to a dataflow-resolved target.
    // The consuming instruction remains in instruction_id.
    std::vector<std::uint64_t> producer_instruction_ids;
    ReferenceProducerGraph producer_graph;
    std::optional<ElfReferenceProvenance> elf;
    std::optional<ElfVTableReferenceProvenance> elf_vtable;
    std::optional<MachOReferenceProvenance> macho;
    std::shared_ptr<const MachODyldReferenceProvenance> dyld;
    // Execution mode proven for an interworking ARM code target. The address
    // remains normalized; this preserves the BX/BLX mode decision for display
    // and mode-aware navigation.
    std::optional<ExecutionMode> target_mode;
};
struct Reference {
    ReferenceId id;
    Location source;
    std::optional<std::uint32_t> operand_index;
    ReferenceTarget target;
    ReferenceKind kind;
    OperandAccess access;
    ReferenceProvenance provenance;
    std::optional<Location> association;
};
struct ReferencePage {
    std::vector<Reference> rows;
    std::uint64_t total = 0;
    std::optional<std::uint64_t> next_offset;
};
class ReferenceIndex {
  public:
    HEXLAB_ANALYSIS_EXPORT static Result<std::shared_ptr<const ReferenceIndex>>
    create(std::vector<Reference>, std::optional<AnalysisKey>, bool complete, std::stop_token);
    HEXLAB_ANALYSIS_EXPORT Result<ReferencePage> incoming(Location, PageRequest) const;
    // Returns numeric references whose target or resolved association falls
    // within [begin, begin + size). Intended for xrefs into typed data objects.
    HEXLAB_ANALYSIS_EXPORT Result<ReferencePage> incoming_range(Address begin, std::uint64_t size,
                                                                 PageRequest) const;
    // Returns references whose source falls within [begin, begin + size).
    // The page follows source-address order and includes every reference kind.
    HEXLAB_ANALYSIS_EXPORT Result<ReferencePage> outgoing_range(Address begin, std::uint64_t size,
                                                                 PageRequest) const;
    // File-offset variants include references whose source/target is a file
    // location; incoming queries also match resolved associations.
    HEXLAB_ANALYSIS_EXPORT Result<ReferencePage> incoming_file_range(FileOffset begin, std::uint64_t size,
                                                                       PageRequest) const;
    HEXLAB_ANALYSIS_EXPORT Result<ReferencePage> outgoing_file_range(FileOffset begin, std::uint64_t size,
                                                                       PageRequest) const;
    // File-backed queries also include virtual references to any image
    // mapping that covers the requested file bytes. Pass the image used to
    // derive this index. Aliased mappings are all
    // considered; rows are de-duplicated and returned in stable index order.
    HEXLAB_ANALYSIS_EXPORT Result<ReferencePage> incoming_mapped_file_range(const Image &, FileOffset begin,
                                                                              std::uint64_t size, PageRequest) const;
    HEXLAB_ANALYSIS_EXPORT Result<ReferencePage> outgoing_mapped_file_range(const Image &, FileOffset begin,
                                                                              std::uint64_t size, PageRequest) const;
    HEXLAB_ANALYSIS_EXPORT Result<ReferencePage> outgoing(Location, PageRequest) const;
    HEXLAB_ANALYSIS_EXPORT Result<ReferencePage> incoming_external(const ExternalIdentity &, PageRequest) const;
    HEXLAB_ANALYSIS_EXPORT Result<ReferencePage> incoming_elf_symbol(const ElfSymbolIdentity &, PageRequest) const;
    HEXLAB_ANALYSIS_EXPORT Result<ReferencePage> incoming_macho_symbol(const MachOSymbolIdentity &, PageRequest) const;
    HEXLAB_ANALYSIS_EXPORT Result<ReferenceProducerGraph> producer_graph(ReferenceId) const;
    std::span<const Reference> all() const noexcept { return references_; }
    const std::optional<AnalysisKey> &key() const noexcept { return key_; }
    std::size_t unresolved_count() const noexcept { return unresolved_; }
    bool complete() const noexcept { return complete_; }
    // Borrows immutable rows; retain this index while using the returned view.
    HEXLAB_ANALYSIS_EXPORT std::span<const Reference> outgoing_view(Location) const noexcept;

  private:
    using LocationKey = std::tuple<unsigned, std::uint32_t, std::uint64_t>;
    static LocationKey location_key(Location) noexcept;
    Result<ReferencePage> page(const std::vector<std::size_t> *, PageRequest) const;
    std::vector<Reference> references_;
    std::optional<AnalysisKey> key_;
    bool complete_ = true;
    std::size_t unresolved_ = 0;
    std::map<LocationKey, std::vector<std::size_t>> incoming_, outgoing_;
    std::map<std::uint64_t, std::size_t> identities_;
    std::map<std::string, std::vector<std::size_t>> external_;
    std::map<std::string, std::vector<std::size_t>> elf_symbols_;
    std::map<std::string, std::vector<std::size_t>> macho_symbols_;
};
inline constexpr std::uint32_t reference_cache_version = 30;
inline constexpr std::size_t reference_record_limit = 4000000, reference_payload_limit = 64 * 1024 * 1024;
HEXLAB_ANALYSIS_EXPORT Result<std::shared_ptr<const ReferenceIndex>>
derive_references(const FunctionSnapshot &, const ImageMetadata &, const AnalysisDecisions &, std::stop_token);
HEXLAB_ANALYSIS_EXPORT Result<std::shared_ptr<const ReferenceIndex>>
derive_references(const Image &, const FunctionSnapshot &, const ImageMetadata &, const AnalysisDecisions &,
                  std::stop_token);
HEXLAB_ANALYSIS_EXPORT Result<std::vector<std::byte>> encode_reference_index(const ReferenceIndex &, std::stop_token);
HEXLAB_ANALYSIS_EXPORT Result<std::shared_ptr<const ReferenceIndex>> decode_reference_index(std::span<const std::byte>,
                                                                                            std::stop_token);
} // namespace hexlab
