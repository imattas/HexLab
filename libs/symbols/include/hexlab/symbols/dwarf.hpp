#pragma once

#include "hexlab/core/result.hpp"
#include "hexlab/symbols/symbols_export.hpp"
#include "hexlab/types/types.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace hexlab::symbols {

struct DwarfV4Sections {
    std::string source_id;
    std::span<const std::uint8_t> info;
    std::span<const std::uint8_t> abbrev;
    std::span<const std::uint8_t> strings;
    std::stop_token stop;
    // Optional legacy .debug_loc section for DWARF v2-v4 location lists.
    std::span<const std::uint8_t> locations;
    // Optional legacy .debug_ranges section for DW_AT_ranges on subprograms.
    std::span<const std::uint8_t> ranges;
};

// Identity parsed from the bounded DWARF v5 .debug_sup header. `filename` is
// an untrusted hint; the top-level file loader restricts it to a same-directory
// basename before opening any supplementary source.
struct DwarfSupplementaryIdentity {
    bool present = false;
    std::uint16_t version = 5;
    bool supplementary = false;
    std::string filename;
    std::vector<std::uint8_t> checksum;
    bool operator==(const DwarfSupplementaryIdentity &) const = default;
};
struct DwarfSupplementaryType {
    // Echo the application object's .debug_sup descriptor only after the
    // callback has verified the selected supplementary object's identity.
    DwarfSupplementaryIdentity identity;
    types::TypePtr type;
    std::uint64_t die_offset = ~std::uint64_t{0};
    std::uint64_t bytes_examined = 0;
    bool identity_verified = false;
};
using DwarfSupplementaryTypeResolver = std::function<hexlab::Result<DwarfSupplementaryType>(
    const DwarfSupplementaryIdentity &, std::uint64_t)>;

struct DwarfSplitUnitRequest {
    std::uint64_t dwo_id = 0;
    std::string dwo_name;
    std::string compilation_directory;
    std::uint8_t address_size = 0;
};
struct ImportResult;
using DwarfSplitUnitResolver = std::function<hexlab::Result<std::shared_ptr<ImportResult>>(
    const DwarfSplitUnitRequest &)>;

// DWARF v5 DWP package index. The index is parsed once and can be captured by
// a caller-owned DwarfSplitUnitResolver. Section IDs are the DW_SECT_* values
// from DWARF v5 section 7.3.5.3 (for example INFO=1 and ABBREV=3).
enum class DwarfPackageIndexKind : std::uint8_t { compile_units, type_units };
struct DwarfPackageIndexLimits {
    std::size_t max_index_bytes = 64u * 1024u * 1024u;
    std::uint32_t max_columns = 8;
    std::uint32_t max_units = 1'000'000;
    std::uint32_t max_slots = 2'000'000;
};
struct DwarfPackageSectionContribution {
    std::uint32_t section_id = 0;
    std::uint32_t offset = 0;
    std::uint32_t size = 0;
    bool operator==(const DwarfPackageSectionContribution &) const = default;
};
struct DwarfPackageIndexRow {
    std::uint64_t signature = 0;
    std::vector<DwarfPackageSectionContribution> sections;
    bool operator==(const DwarfPackageIndexRow &) const = default;
};
struct DwarfPackageIndex {
    DwarfPackageIndexKind kind = DwarfPackageIndexKind::compile_units;
    std::uint32_t version = 5;
    std::vector<std::uint32_t> section_ids;
    // Hash slots retain their on-disk values; row index 0 denotes an empty slot,
    // while used rows are 1-based indexes into `rows`.
    std::vector<std::uint64_t> slot_signatures;
    std::vector<std::uint32_t> slot_rows;
    std::vector<DwarfPackageIndexRow> rows;
    bool operator==(const DwarfPackageIndex &) const = default;
};
struct DwarfPackageSectionData {
    std::uint32_t section_id = 0;
    std::span<const std::uint8_t> bytes;
};
struct DwarfPackageSectionSlice {
    std::uint32_t section_id = 0;
    std::span<const std::uint8_t> bytes;
    std::uint32_t section_offset = 0;
};
struct DwarfPackageContribution {
    std::uint64_t signature = 0;
    std::vector<DwarfPackageSectionSlice> sections;
};

// Resolve a type-unit signature against a parsed TU package index. The resolver
// retains the package's section-offset identity across indexed contributions
// and imports referenced type units on demand. The shared index and all section
// and string spans must remain alive until the returned resolver is discarded.
using DwarfTypeSignatureResolver = std::function<hexlab::Result<types::TypePtr>(std::uint64_t)>;
enum class DwarfReferencedDieKind : std::uint8_t { type, subprogram, variable };
// Identity-preserving summary of one DIE outside the currently imported
// .debug_info contribution. A caller-owned resolver must select the row from
// the already-chosen package index and set identity_verified only after
// checking that row and its contribution bounds.
struct DwarfCrossContributionDie {
    std::uint64_t info_section_offset = 0;
    std::uint64_t die_offset = 0;
    std::uint64_t contribution_signature = 0;
    std::uint64_t contribution_size = 0;
    DwarfPackageIndexKind index_kind = DwarfPackageIndexKind::compile_units;
    DwarfReferencedDieKind kind = DwarfReferencedDieKind::type;
    std::string name;
    types::TypePtr type;
    std::uint64_t bytes_examined = 0;
    bool identity_verified = false;
};
using DwarfCrossContributionDieResolver = std::function<hexlab::Result<DwarfCrossContributionDie>(
    std::uint64_t absolute_info_offset)>;
using DwarfSourceCrossContributionDieResolver = std::function<hexlab::Result<DwarfCrossContributionDie>(
    std::string_view source_id, std::uint64_t absolute_info_offset)>;
struct DwarfPackageTypeResolutionLimits {
    std::uint64_t max_bytes = 64u * 1024u * 1024u;
    std::uint32_t max_requests = 4096;
};
// One caller-selected DWARF type-unit package in a bounded resolver catalog.
// The caller must keep the index, section buffers, and string tables alive for
// the returned resolver's lifetime and set identity_verified only after
// checking the package against its selected binary/build-id or supplement ID.
struct DwarfTypeUnitPackage {
    std::string source_id;
    std::shared_ptr<const DwarfPackageIndex> index;
    std::vector<DwarfPackageSectionData> sections;
    std::span<const std::uint8_t> strings;
    std::span<const std::uint8_t> line_strings;
    DwarfCrossContributionDieResolver cross_contribution_die_resolver;
    bool identity_verified = false;
};
// A selected CU-indexed DWO/DWP source for exact DW_FORM_ref_addr resolution.
struct DwarfCompileUnitPackage {
    std::string source_id;
    std::shared_ptr<const DwarfPackageIndex> index;
    std::vector<DwarfPackageSectionData> sections;
    std::span<const std::uint8_t> strings;
    std::span<const std::uint8_t> line_strings;
    bool identity_verified = false;
};
HEXLAB_SYMBOLS_EXPORT DwarfSourceCrossContributionDieResolver make_dwarf_package_catalog_cross_contribution_die_resolver(
    std::vector<DwarfCompileUnitPackage> packages, std::stop_token stop = {},
    DwarfPackageTypeResolutionLimits limits = {});
// Builds one bounded DW_FORM_ref_sig8 resolver across up to 64 explicitly
// selected DWP type indexes. Dependencies can cross packages; duplicate
// signatures are rejected as ambiguous rather than guessed.
HEXLAB_SYMBOLS_EXPORT DwarfTypeSignatureResolver make_dwarf_package_catalog_type_signature_resolver(
    std::vector<DwarfTypeUnitPackage> packages, std::stop_token stop = {},
    DwarfPackageTypeResolutionLimits limits = {});

HEXLAB_SYMBOLS_EXPORT hexlab::Result<DwarfPackageIndex> parse_dwarf_package_index(
    std::span<const std::uint8_t> bytes, DwarfPackageIndexKind kind, bool little_endian = true,
    std::stop_token stop = {}, DwarfPackageIndexLimits limits = {});
HEXLAB_SYMBOLS_EXPORT hexlab::Result<DwarfPackageContribution> find_dwarf_package_contribution(
    const DwarfPackageIndex &index, std::uint64_t signature,
    std::span<const DwarfPackageSectionData> sections, std::stop_token stop = {});
HEXLAB_SYMBOLS_EXPORT DwarfTypeSignatureResolver make_dwarf_package_type_signature_resolver(
    std::shared_ptr<const DwarfPackageIndex> index,
    std::vector<DwarfPackageSectionData> sections,
    std::span<const std::uint8_t> strings = {},
    std::span<const std::uint8_t> line_strings = {},
    std::stop_token stop = {}, DwarfPackageTypeResolutionLimits limits = {});
HEXLAB_SYMBOLS_EXPORT DwarfTypeSignatureResolver make_dwarf_package_type_signature_resolver(
    std::shared_ptr<const DwarfPackageIndex> index,
    std::vector<DwarfPackageSectionData> sections,
    std::span<const std::uint8_t> strings,
    std::span<const std::uint8_t> line_strings,
    std::stop_token stop, DwarfPackageTypeResolutionLimits limits,
    DwarfCrossContributionDieResolver cross_contribution_die_resolver);
// Build a package-index-backed resolver for DW_FORM_ref_addr into another
// compile-unit contribution. Offsets must map to exactly one indexed INFO
// contribution and to an imported DIE at that exact section offset.
HEXLAB_SYMBOLS_EXPORT DwarfCrossContributionDieResolver make_dwarf_package_cross_contribution_die_resolver(
    std::shared_ptr<const DwarfPackageIndex> index,
    std::vector<DwarfPackageSectionData> sections,
    std::span<const std::uint8_t> strings = {},
    std::span<const std::uint8_t> line_strings = {},
    std::stop_token stop = {}, DwarfPackageTypeResolutionLimits limits = {});

// Bounded section bundle for the practical DWARF v4/v5 DIE importer. Indexed
// v5 forms use the matching contribution sections when supplied.
struct DwarfSections {
    std::string source_id;
    std::span<const std::uint8_t> info, abbrev, strings, string_offsets, addresses, line_strings;
    // The DWARF4 .debug_types stream uses the type-unit header layout. This is
    // set by bounded package readers that have selected a TU contribution.
    bool dwarf4_type_units = false;
    std::stop_token stop;
    // Optional supplementary object string table used by DW_FORM_strp_sup.
    std::span<const std::uint8_t> supplementary_strings;
    // Optional DWARF v5 location-list contribution section.
    std::span<const std::uint8_t> location_lists;
    // Optional legacy .debug_loc section (DWARF v2-v4).
    std::span<const std::uint8_t> locations;
    // Optional DWARF v5 range-list contribution section used by DW_AT_ranges.
    std::span<const std::uint8_t> range_lists;
    // Optional legacy .debug_ranges section (DWARF v2-v4).
    std::span<const std::uint8_t> ranges;
    // Optional identity from .debug_sup and an explicit caller-owned resolver.
    // Returned identity is compared exactly before a resolved type is used.
    DwarfSupplementaryIdentity supplementary_identity;
    DwarfSupplementaryTypeResolver supplementary_type_resolver;
    // Optional bounded resolver for DW_FORM_ref_sig8 when the target type unit
    // is in a separate but identity-indexed package contribution.
    DwarfTypeSignatureResolver type_signature_resolver;
    // Optional resolver for a `DW_FORM_ref_addr` target in a different
    // already-selected DWO/DWP contribution. Its result must attest exact
    // package-index identity, contribution bounds, and target offset.
    DwarfCrossContributionDieResolver cross_contribution_die_resolver;
    DwarfSourceCrossContributionDieResolver source_cross_contribution_die_resolver;
    std::uint64_t cross_contribution_max_bytes = 64u * 1024u * 1024u;
    std::uint32_t cross_contribution_max_requests = 4096;
    // Per-import limits charged against caller-reported supplementary reads.
    std::uint64_t supplementary_resolution_max_bytes = 64u * 1024u * 1024u;
    std::uint32_t supplementary_resolution_max_requests = 100000;
    // Optional resolver for DWARF v5 skeleton units. It receives the stable
    // DWO ID plus the untrusted path hints from the skeleton DIE. The caller
    // owns file discovery, identity verification, and parsing of the DWO or
    // DWP contribution; returned ImportResult::split_dwo_id is checked here.
    DwarfSplitUnitResolver split_unit_resolver;
    // Set by a caller importing a DWO/DWP contribution. Every unit in the
    // contribution must be a split unit with this exact ID.
    std::optional<std::uint64_t> expected_split_dwo_id;
    std::optional<std::uint8_t> expected_split_address_size;
    // Original offset of `info` within the package's shared .debug_info section.
    // Zero for standalone objects and contributions without a package base.
    std::uint64_t info_section_offset = 0;
};

// DWARF v2-v5 line-program address row. File numbers are one-based indexes
// into `files`. File-table directory index 0 means the current compilation
// directory; 1 and above index the returned `directories` vector from 0.
struct DwarfLineRow {
    std::uint64_t address = 0;
    std::uint64_t file = 1;
    std::int64_t line = 1;
    std::uint64_t column = 0;
    bool end_sequence = false;
    bool operator==(const DwarfLineRow &) const = default;
};
struct DwarfLineFile {
    std::string name;
    std::uint64_t directory = 0, modification_time = 0, size = 0;
    bool operator==(const DwarfLineFile &) const = default;
};
struct DwarfLineUnit {
    std::uint16_t version = 0;
    std::string source_id;
    std::uint64_t section_offset = 0;
    std::vector<std::string> directories;
    std::vector<DwarfLineFile> files;
    std::vector<DwarfLineRow> rows;
    bool operator==(const DwarfLineUnit &) const = default;
};

// Opaque macro data attached to the split unit selected by a DWP package
// index. The bytes are one bounded DW_SECT_MACRO contribution; strings remain
// the package's shared tables so consumers can interpret indexed operands
// without losing the original contribution provenance.
struct DwarfMacroContribution {
    std::string source_id;
    DwarfPackageIndexKind index_kind = DwarfPackageIndexKind::compile_units;
    std::uint32_t package_index_version = 0;
    std::uint64_t signature = 0;
    std::uint32_t section_id = 0;
    std::uint64_t section_offset = 0;
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> strings;
    std::vector<std::uint8_t> line_strings;
    bool operator==(const DwarfMacroContribution &) const = default;
};
struct DwarfLineSections {
    std::string source_id;
    std::span<const std::uint8_t> line;
    std::uint8_t address_size = 8;
    bool little_endian = true;
    std::size_t max_rows = 4'000'000;
    std::stop_token stop;
    // Optional shared string sections used by DWARF v5 line-table forms.
    std::span<const std::uint8_t> strings, line_strings;
    // Absolute offset of this byte span in its source section. Contribution
    // importers use this to retain package-level provenance on each unit.
    std::uint64_t section_offset = 0;
};
HEXLAB_SYMBOLS_EXPORT hexlab::Result<std::vector<DwarfLineUnit>> import_dwarf_line_v2_v5(const DwarfLineSections &sections);
// Compatibility name retained for callers that explicitly request v2-v4.
HEXLAB_SYMBOLS_EXPORT hexlab::Result<std::vector<DwarfLineUnit>> import_dwarf_line_v2_v4(const DwarfLineSections &sections);
// Returns the source row covering an address within a terminated line
// sequence. End-sequence rows are exclusive bounds, and incomplete sequences
// are not extended past their last recorded row.
HEXLAB_SYMBOLS_EXPORT std::optional<DwarfLineRow> dwarf_line_row_at(const DwarfLineUnit &unit,
                                                                    std::uint64_t address) noexcept;

struct SourceOrigin {
    std::string source_id;
    std::string section;
    std::uint64_t unit_offset = 0;
    std::uint64_t record_offset = 0;
    std::uint64_t record_size = 0;
    bool operator==(const SourceOrigin &) const = default;
};

enum class DwarfMacroRecordKind : std::uint8_t { define, undefine, start_file, end_file };
struct DwarfMacroRecord {
    DwarfMacroRecordKind kind = DwarfMacroRecordKind::define;
    SourceOrigin origin;
    std::uint64_t line = 0;
    std::optional<std::uint64_t> file_index;
    std::optional<std::string> file_name;
    std::string file_source_id;
    std::string text;
    bool operator==(const DwarfMacroRecord &) const = default;
};
struct DwarfMacroUnit {
    std::string source_id;
    std::uint16_t version = 0;
    std::uint64_t section_offset = 0;
    std::optional<std::uint64_t> line_table_offset;
    std::vector<DwarfMacroRecord> records;
    bool operator==(const DwarfMacroUnit &) const = default;
};
struct DwarfMacroSections {
    std::string source_id;
    std::span<const std::uint8_t> macro, strings;
    std::span<const DwarfLineUnit> line_units;
    std::uint64_t section_offset = 0;
    bool little_endian = true;
    std::size_t max_units = 65536;
    std::size_t max_records = 1'000'000;
    std::size_t max_text_bytes = 64u * 1024u * 1024u;
    std::stop_token stop;
};
// Parses bounded DWARF v5 macro units for inline/strp define and undef records
// plus start_file/end_file scope records. Supplementary, indexed-string, and
// imported macro units fail explicitly as unsupported.
HEXLAB_SYMBOLS_EXPORT hexlab::Result<std::vector<DwarfMacroUnit>> import_dwarf_macro_v5(
    const DwarfMacroSections &sections);

struct DwarfDeclarationLocation {
    // Raw DW_AT_decl_file index in the owning unit's line table.
    std::optional<std::uint64_t> file_index;
    std::optional<std::uint64_t> line, column;
    bool operator==(const DwarfDeclarationLocation &) const = default;
};

// An entry_point is an alternate code entry and does not imply a complete
// DW_TAG_subprogram extent or callable function type.
enum class SymbolKind : std::uint8_t { function, object, entry_point };

struct ImportedSymbol {
    std::string name;
    SymbolKind kind = SymbolKind::function;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    SourceOrigin origin;
    // Function prototypes are attached when formal-parameter and return-type
    // DIEs resolve successfully.
    types::TypePtr type;
    struct Range { std::uint64_t begin = 0, end = 0; bool operator==(const Range &) const = default; };
    std::vector<Range> ranges;
    // Raw standard DW_AT_linkage_name from this ranged subprogram DIE, when present.
    std::optional<std::string> linkage_name;
    // Direct declaration coordinates from this subprogram DIE, when present.
    std::optional<DwarfDeclarationLocation> declaration_location;
    bool operator==(const ImportedSymbol &) const = default;
};

struct ImportedType {
    types::TypePtr type;
    SourceOrigin origin;
    // DWARF v4 has no portable base-type alignment attribute. The importer
    // assigns alignment 1 as an explicit unknown/conservative placeholder.
    bool alignment_is_inferred = true;
    std::string source_name;
    bool is_typedef = false;
    bool is_const = false;
    bool is_volatile = false;
    bool is_restrict = false;
    bool is_atomic = false;
    bool operator==(const ImportedType &) const = default;
};

// Type-unit signature exported with the owning DIE's checked source location.
struct ImportedTypeSignature {
    std::uint64_t signature = 0;
    types::TypePtr type;
    SourceOrigin origin;
    bool operator==(const ImportedTypeSignature &) const = default;
};

// A validated DWARF v2-v5 location-expression instruction. The
// decoder accepts address, literal/register/base-register, fbreg/CFA, constant,
// dereference, TLS address conversion, integer stack manipulation/arithmetic and signed comparisons,
// plus, piece/bit_piece, stack_value, implicit scalar values, entry_value, and bra/skip operations.
// Entry-value blocks nest at most 16 levels and share a 4096-operation decode
// budget. Other opcodes return ErrorCode::unsupported; truncated operands and
// invalid branch targets return malformed. Register numbers are target-defined;
// runtime register values are never invented.
// Unused operands are 0.
enum class LocationOperationKind : std::uint8_t {
    address, literal, register_location, base_register_plus_offset,
    frame_base_relative, call_frame_cfa, tls_address, unsigned_constant, signed_constant,
    dereference, dereference_sized, plus, plus_unsigned, piece, bit_piece,
    stack_value, implicit_value, stack_operation, branch, branch_if_nonzero, entry_value
};

struct LocationOperation {
    LocationOperationKind kind = LocationOperationKind::literal;
    std::uint64_t unsigned_operand = 0;
    std::int64_t signed_operand = 0;
    std::uint32_t expression_offset = 0;
    std::uint64_t second_unsigned_operand = 0;
    std::vector<std::uint8_t> block_operand;
    std::vector<LocationOperation> nested_operations;
    bool operator==(const LocationOperation &) const = default;
};

enum class EvaluatedLocationKind : std::uint8_t { memory, register_location, value };
struct EvaluatedLocation {
    EvaluatedLocationKind kind = EvaluatedLocationKind::memory;
    std::uint64_t value = 0; // address, register number, or scalar value by kind
    bool operator==(const EvaluatedLocation &) const = default;
};
// Runtime inputs are supplied by the caller. The evaluator never reads a
// process itself; absent registers, frame/CFA bases, or memory are errors.
struct LocationEvaluationContext {
    std::uint8_t address_size = 8;
    bool target_big_endian = false;
    std::optional<std::uint64_t> frame_base;
    std::optional<std::uint64_t> call_frame_cfa;
    std::function<std::optional<std::uint64_t>(std::uint64_t)> read_register;
    // Entry-state registers are distinct from current stopped-state registers.
    // This callback is used only inside DW_OP_entry_value nested expressions.
    std::function<std::optional<std::uint64_t>(std::uint64_t)> read_entry_register;
    // Resolve a DW_OP_form_tls_address offset for the selected stopped thread.
    // The evaluator does not infer a module TLS base or read process state.
    std::function<std::optional<std::uint64_t>(std::uint64_t)> resolve_tls_address;
    std::function<hexlab::Result<std::uint64_t>(std::uint64_t, std::uint8_t)> read_memory;
    // Entry-state memory is distinct from current memory and is used only
    // inside DW_OP_entry_value nested expressions.
    std::function<hexlab::Result<std::uint64_t>(std::uint64_t, std::uint8_t)> read_entry_memory;
};
HEXLAB_SYMBOLS_EXPORT hexlab::Result<EvaluatedLocation> evaluate_location_expression(
    std::span<const LocationOperation> operations, const LocationEvaluationContext &context);

struct LocationRange {
    std::uint64_t begin = 0;
    std::uint64_t end = 0; // exclusive
    std::vector<std::uint8_t> expression;
    std::vector<LocationOperation> operations;
    bool operator==(const LocationRange &) const = default;
};

struct ImportedVariable {
    std::string name;
    types::TypePtr type;
    bool is_parameter = false;
    std::uint64_t scope_offset = 0;
    std::optional<std::uint64_t> address;
    std::vector<std::uint8_t> location_expression;
    SourceOrigin origin;
    // Decoded operations corresponding to location_expression. A bounded CFA
    // offset is derived when the function frame base and expression are known.
    std::vector<LocationOperation> location_operations;
    // Derived only for bounded frame/CFA-relative expressions with a known
    // canonical CFA frame base. This is an offset, never a fabricated address.
    std::optional<std::int64_t> cfa_offset;
    // DWARF v2-v5 PC-scoped expressions, retained as ranges instead of
    // flattened to whichever entry happens to match during import.
    std::vector<LocationRange> location_ranges;
    // Direct declaration coordinates from this variable/parameter DIE.
    std::optional<DwarfDeclarationLocation> declaration_location;
    bool operator==(const ImportedVariable &) const = default;
};

// Selects and evaluates an imported variable's location at the requested PC.
// A variable with location ranges must match one half-open range; an un-ranged
// expression or direct address is evaluated/returned only when no ranges exist.
// Runtime register and memory access remains entirely caller supplied.
HEXLAB_SYMBOLS_EXPORT hexlab::Result<EvaluatedLocation> evaluate_imported_variable_location(
    const ImportedVariable &variable, std::uint64_t pc, const LocationEvaluationContext &context);

struct ImportedEnumerator {
    struct ExactValue {
        // Exact storage bits interpreted according to is_signed and the enum's
        // underlying type. Negative signed values use two's-complement bits.
        std::uint64_t bits = 0;
        bool is_signed = true;
        bool operator==(const ExactValue &) const = default;
    };
    std::string name;
    std::string enum_type_name;
    // Legacy signed projection retained for source compatibility. Consumers
    // should prefer exact_value when it is present.
    std::int64_t value = 0;
    SourceOrigin origin;
    // Appended so existing four-field aggregate initializers remain valid.
    std::optional<ExactValue> exact_value;
    bool operator==(const ImportedEnumerator &) const = default;
};

struct ImportResult {
    std::vector<ImportedSymbol> symbols;
    std::vector<ImportedType> types;
    std::vector<ImportedTypeSignature> type_signatures;
    std::vector<ImportedVariable> variables;
    std::vector<ImportedEnumerator> enumerators;
    std::vector<DwarfLineUnit> line_units;
    std::vector<DwarfMacroContribution> macro_contributions;
    std::vector<DwarfMacroUnit> macro_units;
    bool split_unit = false;
    std::optional<std::uint64_t> split_dwo_id;
    std::vector<std::string> diagnostics;
    bool operator==(const ImportResult &) const = default;
};

// Imports a bounded DWARF v4 subset: base/derived/aggregate types, array bounds,
// enum constants, prototypes, subprograms, parameters, and variables. Type
// references resolve only within the current unit. Recursive aggregate graphs
// and unsupported location expressions/forms return an explicit error. Legacy
// .debug_loc and .debug_ranges lists are accepted through the matching spans;
// this is not a complete DWARF reader. Section spans are borrowed only during
// the call.
HEXLAB_SYMBOLS_EXPORT hexlab::Result<ImportResult> import_dwarf_v4(const DwarfV4Sections &sections);
// Imports the same DIE/type subset from DWARF v4 and ordinary v5 compile
// units. Legacy v2-v4 .debug_loc/.debug_ranges and v5
// .debug_loclists/.debug_rnglists are optional inputs.
// Indexed forms resolve only through supplied contribution sections
// and explicit compilation-unit base attributes. Ranged subprogram DIEs may
// inherit missing names, return types, and parameter lists through same-unit
// DW_AT_specification/DW_AT_abstract_origin references.
HEXLAB_SYMBOLS_EXPORT hexlab::Result<ImportResult> import_dwarf(const DwarfSections &sections);

// Imports one bounded DWARF v2/v5 DWP compile-unit contribution. The caller
// owns package discovery and section extraction; strings and line_strings are
// the shared DWO string sections. LINE and RNGLISTS contributions are consumed
// when present; a matching indexed macro contribution is retained as raw
// bytes with package-index provenance and parsed for the bounded v5 macro
// subset. Indexed contributions are selected by DWO ID, which is carried in
// the returned result.
HEXLAB_SYMBOLS_EXPORT hexlab::Result<ImportResult> import_dwarf_package_unit(
    const DwarfPackageIndex &index, std::uint64_t dwo_id,
    std::span<const DwarfPackageSectionData> sections,
    std::span<const std::uint8_t> strings, std::stop_token stop = {},
    std::span<const std::uint8_t> line_strings = {}, std::uint8_t address_size = 8,
    bool little_endian = true, DwarfTypeSignatureResolver type_signature_resolver = {});
HEXLAB_SYMBOLS_EXPORT hexlab::Result<ImportResult> import_dwarf_package_unit(
    const DwarfPackageIndex &index, std::uint64_t dwo_id,
    std::span<const DwarfPackageSectionData> sections,
    std::span<const std::uint8_t> strings, std::stop_token stop,
    std::span<const std::uint8_t> line_strings, std::uint8_t address_size,
    bool little_endian, DwarfTypeSignatureResolver type_signature_resolver,
    DwarfCrossContributionDieResolver cross_contribution_die_resolver);

} // namespace hexlab::symbols
