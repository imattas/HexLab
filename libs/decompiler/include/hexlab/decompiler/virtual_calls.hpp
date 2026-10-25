#pragma once

#include "hexlab/decompiler/decompiler_export.hpp"
#include "hexlab/types/types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hexlab::decompiler {

// Facts needed to annotate (but not de-indirect) a machine virtual call. The
// caller must establish receiver identity and the byte offset of the vtable
// slot from the lifted expression; this API deliberately does not guess either.
struct VirtualCallEvidence {
    types::TypePtr receiver_class;
    // Supported native pointer width in bytes (4 for x86, 8 for x64).
    std::uint8_t pointer_bytes = 0;
    std::uint32_t slot_byte_offset = 0;
    // When known, identifies the object offset of the vftable pointer. The
    // analyzer then requires a persisted CodeView LF_VFTABLE slot record.
    std::optional<std::uint32_t> vftable_pointer_offset;
    types::TypePtr exact_signature;
    // Human-readable origin for the receiver/slot proof, normally a PDB type
    // and vftable symbol. Kept verbatim so UI/reporting can show provenance.
    std::string provenance;
};

struct VirtualCallCandidate {
    std::string method_name;
    std::uint32_t declaration_ordinal = 0;
    std::uint32_t slot_byte_offset = 0;
    types::TypePtr signature;
    std::string provenance;
};

struct VirtualCallAnalysis {
    std::vector<VirtualCallCandidate> candidates;
    bool ambiguous = false;
    // True only when exactly one method declaration matched every supplied
    // fact. This remains an annotation: callers must keep the IR target indirect
    // until a vftable entry's runtime address is independently validated.
    bool uniquely_typed = false;
};

// Finds declarations that exactly match a known class, slot byte offset, and
// function type. Only methods carrying an explicit introducing-vtable offset
// are eligible; inherited/overridden slots without explicit slot metadata are
// intentionally left unknown.
HEXLAB_DECOMPILER_EXPORT VirtualCallAnalysis analyze_virtual_call(
    const VirtualCallEvidence &evidence);

} // namespace hexlab::decompiler
