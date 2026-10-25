#include "hexlab/workspace/project.hpp"
#include <algorithm>
#include <tuple>
namespace hexlab {
CommandAvailability action_availability(const ProjectSnapshot *snapshot, ProjectActionKind kind,
                                        std::optional<Location> selection) {
    auto no = [](const char *reason) { return CommandAvailability{false, reason}; };
    if (static_cast<unsigned>(kind) > static_cast<unsigned>(ProjectActionKind::reset_function))
        return no("Unknown project action");
    if (!snapshot || !snapshot->state || !snapshot->effective || !snapshot->original)
        return no("Open a binary or project first");
    auto &project = *snapshot;
    auto &state = *project.state;
    if (kind == ProjectActionKind::save_as || kind == ProjectActionKind::export_binary)
        return {true, {}};
    if (kind == ProjectActionKind::reanalyze)
        return project.loaded ? CommandAvailability{true, {}} : no("Restore a valid image mapping before analysis");
    if (kind == ProjectActionKind::search)
        return project.effective->size() ? CommandAvailability{true, {}} : no("The input contains no bytes");
    if(kind==ProjectActionKind::define_type)return {true,{}};
    if(kind==ProjectActionKind::import_symbols)return importable_symbols(project).empty()?no("No symbols are available to import"):CommandAvailability{true,{}};
    if (kind == ProjectActionKind::import_dwarf)
        return project.mode == database::ProjectMode::read_write && project.loaded && project.loaded->metadata.elf &&
                       project.loaded->metadata.elf->dwarf_info
                   ? CommandAvailability{true, {}}
                   : no("This project has no writable, supported ELF DWARF type/symbol information");
    if (project.mode == database::ProjectMode::read_only)
        return no("This project is read-only");
    if (kind == ProjectActionKind::save)
        return {true, {}};
    if (kind == ProjectActionKind::undo)
        return state.history_cursor ? CommandAvailability{true, {}} : no("No command to undo");
    if (kind == ProjectActionKind::redo)
        return state.history_cursor < state.history_count ? CommandAvailability{true, {}} : no("No command to redo");
    if (!selection)
        return no("Select a location first");
    auto address = std::get_if<Address>(&*selection);
    bool mapped = false, initialized = false;
    if (address && project.loaded) {
        auto segment = project.loaded->image->segment_at(*address);
        mapped = segment != nullptr;
        initialized = segment && address->offset - segment->begin.offset < segment->file_size;
    } else if (auto file = std::get_if<FileOffset>(&*selection)) {
        mapped = file->value < project.effective->size();
        initialized = mapped;
    }
    bool retained = false;
    if (!mapped && (kind == ProjectActionKind::rename || kind == ProjectActionKind::comment))
        retained = annotation_at(project, *selection) != nullptr;
    if (!mapped && kind == ProjectActionKind::bookmark)
        for (auto &bookmark : state.user->bookmarks)
            if (bookmark.location == *selection) {
                retained = true;
                break;
            }
    if (!mapped && !retained)
        return no("The location is outside the current mapping");
    if (kind == ProjectActionKind::rename)
        return address ? CommandAvailability{true, {}} : no("Names require a virtual address");
    if(kind==ProjectActionKind::assign_type)return address?CommandAvailability{true,{}}:no("Types require a virtual address");
    if (kind == ProjectActionKind::comment || kind == ProjectActionKind::bookmark ||
        kind == ProjectActionKind::reference)
        return {true, {}};
    if (kind == ProjectActionKind::patch) {
        if (address && project.loaded && project.loaded->image->storage() != project.effective &&
            !project.loaded->metadata.firmware)
            return no("Virtual-address patches are unsupported for this structured image");
        return initialized ? CommandAvailability{true, {}} : no("Patches require initialized file bytes");
    }
    if (!address || !project.loaded)
        return no("This action requires a virtual address");
    if (kind == ProjectActionKind::reset_function) {
        const bool has_override = std::any_of(state.user->decisions.functions.begin(), state.user->decisions.functions.end(),
                                               [&](const auto &row) { return row.entry == *address; });
        return has_override ? CommandAvailability{true, {}} : no("This function has no explicit override to reset");
    }
    if (!initialized)
        return no("This location has no initialized file bytes");
    if (project.status != DerivedStatus::fresh && project.status != DerivedStatus::incomplete)
        return no("Wait for current instruction boundaries");
    if (kind != ProjectActionKind::define_data) {
        const auto context = project.loaded->image->context_at(*address);
        if (!context || !processor_capabilities(context.value()).can_decode)
            return no("Code decisions require a supported processor mode");
    }
    if (project.functions) {
        auto &instructions = project.functions->instructions;
        auto upper =
            std::upper_bound(instructions.begin(), instructions.end(), *address, [](Address at, const auto &fact) {
                const auto other = fact->instruction.address;
                return std::tie(at.space.value, at.offset) < std::tie(other.space.value, other.offset);
            });
        if (upper != instructions.begin()) {
            auto &previous = (*std::prev(upper))->instruction;
            if (previous.address.space == address->space && previous.address.offset < address->offset &&
                address->offset - previous.address.offset < previous.length)
                return no("The location cuts an existing instruction");
        }
    }
    if (kind == ProjectActionKind::function_chunks || kind == ProjectActionKind::suppress_function) {
        bool found = false;
        if (project.functions)
            for (auto &function : project.functions->functions)
                if (function->entry == *address) {
                    found = true;
                    break;
                }
        if (!found)
            for (auto &definition : state.user->decisions.functions)
                if (definition.entry == *address) {
                    found = true;
                    break;
                }
        if (!found)
            return no("Select an established function entry");
    }
    return {true, {}};
}
} // namespace hexlab
