#pragma once

#include "hexlab/debugger/debugger.hpp"
#include "hexlab/workspace/debug_variables.hpp"
#include "hexlab/image/macho_metadata.hpp"
#include "hexlab/image/pe_metadata.hpp"

#include <functional>
#include <string>
#include <vector>

namespace hexlab { struct ElfMetadata; struct DocumentSnapshot; }
namespace hexlab::desktop {

// A fresh module snapshot is required for every user action. No basename fallback.
struct DebuggerImageMapping {
    std::uint64_t runtime_base = 0, preferred_base = 0, size = 0;
    bool operator==(const DebuggerImageMapping &) const = default;
    std::optional<Address> to_image(const Image &, std::uint64_t) const;
    std::optional<std::uint64_t> to_runtime(const Image &, Address) const;
};
std::optional<DebuggerImageMapping> debugger_image_mapping(
    const DocumentSnapshot &, const std::vector<debugger::ModuleInfo> &,
    Architecture process_architecture, std::string &reason);

struct DebuggerLocalRow {
    std::string name;
    std::string kind;
    std::string location;
    std::string value;
    std::string scope;
};

struct DebuggerStackFrame {
    std::uint64_t runtime_pc = 0;
    std::optional<std::uint64_t> call_frame_cfa;
    std::vector<debugger::RegisterValue> registers;
    std::size_t depth = 0;
};

struct DebuggerSymbolizedAddress {
    Address image_address;
    std::string name;
    std::optional<Address> function_entry;
    std::uint64_t displacement = 0;
    std::optional<std::string> source_location;
};

// Maps a runtime PC in the selected module back to the project's image and
// resolves its containing recovered function or exact symbol and, when line
// metadata covers the image address, its source file/line/column.
std::optional<DebuggerSymbolizedAddress> symbolize_debugger_address(
    const ProjectSnapshot &, const Image &, std::uint64_t runtime_pc,
    std::uint64_t module_base, std::uint64_t module_size);

// Builds a bounded caller chain from the selected stopped thread. The first
// frame is always the live context; caller recovery supports the implemented
// x86-64/AArch64/ARM32/RV32/RV64 ELF CFI, x86-64/AArch64 Mach-O recipes,
// and AMD64/ARM64 PE recipes. ARM frame PCs are code addresses; recovered
// register snapshots retain the return address's Thumb state bit.
std::vector<DebuggerStackFrame> debugger_stack_frames_at(
    const Image &, std::uint64_t runtime_pc, std::uint64_t module_base, std::uint64_t module_size,
    Architecture, const std::vector<debugger::RegisterValue> &,
    const MachOMetadata *,
    const std::function<Result<std::vector<std::byte>>(std::uint64_t, std::size_t)> &read_memory,
    std::size_t max_frames = 64, std::uint64_t preferred_base = 0,
    const ::hexlab::ElfMetadata *elf = nullptr,
    const PeMetadata *pe = nullptr);

// Projects contain link-time addresses while the debugger reports runtime
// addresses. `module_base` is the runtime base of the module represented by
// `image`; registers and memory are the selected stopped frame's live state.
std::vector<DebuggerLocalRow> debugger_locals_at(
    const ProjectSnapshot &, const Image &, std::uint64_t runtime_pc,
    std::uint64_t module_base, Architecture,
    const std::vector<debugger::RegisterValue> &,
    const std::function<Result<std::vector<std::byte>>(std::uint64_t, std::size_t)> &read_memory,
    std::optional<std::uint64_t> call_frame_cfa = {});

} // namespace hexlab::desktop
