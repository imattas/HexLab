#pragma once
#include "hexlab/core/byte_reader.hpp"
#include "hexlab/core/architecture.hpp"
#include "hexlab/core/x86_segments.hpp"
#include "hexlab/image/file_storage.hpp"
#include <optional>
#include <vector>

namespace hexlab {
struct Rva {
    std::uint32_t value;
    bool operator==(const Rva &) const = default;
};
struct AddressSpace {
    AddressSpaceId id;
    std::uint8_t width_bits;
    std::uint8_t unit_bytes;
    ByteOrder order;
    bool operator==(const AddressSpace &) const = default;
};
struct Segment {
    std::string name;
    Address begin;
    std::uint64_t size;
    FileOffset file_begin;
    std::uint64_t file_size;
    bool readable, writable, executable;
    bool operator==(const Segment &) const = default;
};
struct ImageDomain {
    AddressSpace space;
    DecodeContext context;
    bool operator==(const ImageDomain &) const = default;
};
struct ImageCodeRange {
    Address begin;
    std::uint64_t size = 0;
    bool operator==(const ImageCodeRange &) const = default;
};
// A validated code range with an instruction decode context. Unlike
// ImageDomain, ranges share an address space and may select different ISAs.
struct ImageExecutionRange {
    Address begin;
    std::uint64_t size = 0;
    DecodeContext context;
    bool operator==(const ImageExecutionRange &) const = default;
};
struct ImageExecutionProfile {
    // Present profiles are authoritative: addresses outside these ranges are
    // not instruction bytes, even when their containing segment is executable.
    std::vector<ImageExecutionRange> ranges;
    bool operator==(const ImageExecutionProfile &) const = default;
};

enum class ArmCodeKind { a32, thumb, data, unknown, conflict };
enum class ArmContextSourceKind {
    raw_declaration,
    elf_mapping_symbol,
    elf_function_symbol,
    platform_entry,
    user_override
};
struct ArmSourceEvidence {
    FileOffset begin;
    std::uint64_t size = 0;
    bool operator==(const ArmSourceEvidence &) const = default;
};
// A declaration's identity and original file extent, not a proof that the
// referenced bytes have the claimed meaning. Format loaders verify that meaning.
struct ArmContextSource {
    ArmContextSourceKind kind = ArmContextSourceKind::raw_declaration;
    std::uint64_t namespace_id = 0, record_index = 0;
    std::optional<ArmSourceEvidence> evidence;
    bool operator==(const ArmContextSource &) const = default;
};
struct ArmCodeRange {
    Address begin;
    std::uint64_t size = 0;
    ArmCodeKind kind = ArmCodeKind::unknown;
    std::vector<ArmContextSource> sources;
    bool operator==(const ArmCodeRange &) const = default;
};
struct ArmCodeRoot {
    Address at;
    ExecutionMode mode = ExecutionMode::unknown;
    bool known_thumb_it_clear = false;
    std::vector<ArmContextSource> sources;
    bool operator==(const ArmCodeRoot &) const = default;
};
struct ArmImageProfile {
    std::vector<ArmCodeRange> ranges;
    std::vector<ArmCodeRoot> roots;
    bool operator==(const ArmImageProfile &) const = default;
};
enum class X86ImageEnvironment { real386, protected386 };
struct X86ImageBinding {
    AddressSpaceId space;
    std::uint16_t selector;
    std::optional<X86SegmentDescriptor> descriptor;
    bool operator==(const X86ImageBinding &) const = default;
};
struct X86ImageProfile {
    X86ImageEnvironment environment;
    A20Policy a20;
    std::vector<X86ImageBinding> bindings;
    std::optional<std::uint32_t> input_load_address;
    std::optional<std::uint16_t> stack_selector;
    bool operator==(const X86ImageProfile &) const = default;
};
struct ImageLayout {
    AddressSpace space;
    Architecture architecture;
    ExecutionMode mode;
    std::vector<Segment> segments;
    std::vector<Address> entries;
    // Additional domains; the primary domain retains the fields above.
    std::vector<ImageDomain> domains;
    std::optional<X86ImageProfile> x86_profile;
    std::uint8_t stack_address_width = 0;
    bool segmented_memory = false;
    // Canonical disjoint unions, independent of declared segment permissions.
    // Image::create also includes every encrypted range in code_exclusions.
    std::vector<ImageCodeRange> code_exclusions, encrypted_ranges;
    // Present profiles are authoritative: gaps have unknown code state.
    std::optional<ArmImageProfile> arm_profile;
    // Optional format metadata that assigns multiple decoder contexts inside
    // one address space (for example, PE CHPE hybrid code maps).
    std::optional<ImageExecutionProfile> execution_profile;
    bool operator==(const ImageLayout &) const = default;
};
class Image {
  public:
    HEXLAB_IMAGE_EXPORT static Result<std::shared_ptr<const Image>> create(std::shared_ptr<const ByteStorage>,
                                                                           ImageLayout);
    const ImageLayout &layout() const noexcept { return layout_; }
    DecodeContext decode_context() const noexcept {
        return {layout_.architecture, layout_.mode, layout_.space.order, layout_.stack_address_width,
                layout_.segmented_memory};
    }
    HEXLAB_IMAGE_EXPORT const AddressSpace *space(AddressSpaceId) const noexcept;
    HEXLAB_IMAGE_EXPORT Result<DecodeContext> context_at(Address) const;
    HEXLAB_IMAGE_EXPORT Result<X86LogicalAddress> logical_address(Address) const;
    HEXLAB_IMAGE_EXPORT Result<Address> from_logical(X86LogicalAddress) const;
    HEXLAB_IMAGE_EXPORT Result<X86LinearTranslation> linear_spans(Address, std::uint64_t size, X86SegmentAccess) const;
    HEXLAB_IMAGE_EXPORT Result<X86PhysicalTranslation> physical_spans(Address, std::uint64_t size) const;
    HEXLAB_IMAGE_EXPORT Result<Sha256Digest> mapping_fingerprint(std::stop_token = {}) const;
    const std::shared_ptr<const ByteStorage> &storage() const noexcept { return storage_; }
    HEXLAB_IMAGE_EXPORT const Segment *segment_at(Address) const noexcept;
    HEXLAB_IMAGE_EXPORT const ArmCodeRange *arm_code_at(Address) const noexcept;
    HEXLAB_IMAGE_EXPORT const ImageExecutionRange *execution_range_at(Address) const noexcept;
    // Available bytes before the next exclusion; these queries do not grant
    // mapping/execute permission and never read or transform source bytes.
    HEXLAB_IMAGE_EXPORT std::uint64_t code_window(Address, std::uint64_t maximum) const noexcept;
    HEXLAB_IMAGE_EXPORT std::uint64_t plaintext_window(Address, std::uint64_t maximum) const noexcept;
    HEXLAB_IMAGE_EXPORT Result<std::vector<std::byte>> read(Address, std::size_t) const;
    HEXLAB_IMAGE_EXPORT Result<FileOffset> to_file_offset(Address) const;
    HEXLAB_IMAGE_EXPORT Result<Address> to_address(FileOffset) const;

  private:
    Result<bool> validate_profile() const;
    Result<bool> normalize_arm_profile();
    Result<bool> validate_execution_profile() const;
    Image(std::shared_ptr<const ByteStorage> storage, ImageLayout layout)
        : storage_(std::move(storage)), layout_(std::move(layout)) {}
    std::shared_ptr<const ByteStorage> storage_;
    ImageLayout layout_;
};
} // namespace hexlab
