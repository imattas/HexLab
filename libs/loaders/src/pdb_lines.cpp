#include "hexlab/loaders/pdb_lines.hpp"
#include "hexlab/image/file_storage.hpp"
#include <algorithm>
#include <limits>
#include <map>
#include <string_view>

namespace hexlab {
Result<std::size_t> attach_pdb_source_lines(LoadedImage &image,
                                            const types::PdbDatabase &pdb,
                                            const types::PdbSourceLineTable &lines) {
    if (!image.image || !image.metadata.pe)
        return Error{ErrorCode::unsupported, "PDB source lines require a loaded PE image"};
    const auto &identities = image.metadata.pe->codeview;
    const PeCodeViewIdentity *match = nullptr;
    std::size_t matches = 0;
    for (const auto &identity : identities) {
        if (identity.guid == pdb.info.guid && identity.age == pdb.info.age) {
            match = &identity;
            ++matches;
        }
    }
    if (matches != 1) return std::size_t{0};

    std::vector<PeSourceLine> imported;
    imported.reserve(lines.lines.size());
    const auto base = image.load_base.value_or(image.metadata.preferred_base);
    const auto &sections = image.metadata.sections;
    for (const auto &line : lines.lines) {
        PeSourceLine row;
        row.source_path = line.source_path;
        row.source_file_id = line.source_file_id;
        row.checksum_kind = line.checksum_kind;
        row.checksum = line.checksum;
        row.section = line.section;
        row.reloc_offset = line.reloc_offset;
        row.section_offset = line.section_offset;
        row.contribution_size = line.contribution_size;
        row.block_size = line.block_size;
        row.line = line.line;
        row.end_line = line.end_line;
        row.start_column = line.start_column;
        row.end_column = line.end_column;
        row.has_columns = line.has_columns;
        row.is_statement = line.is_statement;
        row.module_name = line.module_name;
        row.object_name = line.object_name;
        row.module_index = line.module_index;
        row.subsection_offset = line.subsection_offset;

        if (line.section != 0 && line.section <= sections.size()) {
            const auto &section = sections[line.section - 1];
            const auto extent = std::max<std::uint64_t>(section.virtual_size, section.raw_size);
            const auto contribution_start = std::uint64_t{line.reloc_offset};
            const auto row_offset = std::uint64_t{line.section_offset};
            const auto contribution = std::uint64_t{line.contribution_size};
            const bool contribution_in_section = contribution_start <= extent &&
                contribution <= extent - contribution_start;
            const bool row_in_section = row_offset < extent && row_offset >= contribution_start &&
                row_offset - contribution_start < contribution;
            const auto contribution_rva = std::uint64_t{section.rva.value} + contribution_start;
            const bool contribution_in_image = contribution_rva <= image.metadata.image_size &&
                contribution <= image.metadata.image_size - contribution_rva;
            const auto rva = std::uint64_t{section.rva.value} + row_offset;
            const bool row_in_image = rva < image.metadata.image_size;
            const bool no_overflow = rva <= std::numeric_limits<std::uint64_t>::max() - base;
            if (contribution_in_section && row_in_section && contribution_in_image && row_in_image && no_overflow)
                row.address = Address{image.image->layout().space.id, base + rva};
        }
        imported.push_back(std::move(row));
    }
    image.metadata.pe->source_lines = std::move(imported);
    return image.metadata.pe->source_lines.size();
}

Result<std::size_t> attach_pdb_locals(LoadedImage &image, const types::PdbDatabase &pdb,
                                      const types::PdbLocalTable &locals) {
    if (!image.image || !image.metadata.pe)
        return Error{ErrorCode::unsupported, "PDB locals require a loaded PE image"};
    std::size_t matches = 0;
    for (const auto &identity : image.metadata.pe->codeview)
        if (identity.guid == pdb.info.guid && identity.age == pdb.info.age) ++matches;
    if (matches != 1) return std::size_t{0};
    const auto base = image.load_base.value_or(image.metadata.preferred_base);
    const auto &sections = image.metadata.sections;
    auto &output = image.metadata.pe->pdb_locals;
    output.clear(); output.reserve(locals.locals.size());
    for (const auto &local : locals.locals) {
        PePdbLocal row;
        row.name = local.name; row.procedure_name = local.procedure_name;
        row.module_name = local.module_name; row.object_name = local.object_name;
        row.type_index = local.type_index; row.parameter = local.parameter;
        row.has_lexical_scope = local.has_lexical_scope;
        row.lexical_scope_section = local.lexical_scope_section;
        row.lexical_scope_offset = local.lexical_scope_offset;
        row.lexical_scope_size = local.lexical_scope_size;
        row.inlinee_id = local.inlinee_id;
        row.inline_site_record_offset = local.inline_site_record_offset;
        row.location_kind = static_cast<PePdbLocalLocationKind>(local.location_kind);
        row.frame_offset = local.frame_offset; row.register_id = local.register_id;
        row.procedure_section = local.procedure_section;
        row.procedure_section_offset = local.procedure_section_offset;
        row.procedure_size = local.procedure_size;
        row.module_index = local.module_index; row.record_kind = local.record_kind;
        row.record_offset = local.record_offset;
        row.live_ranges.reserve(local.live_ranges.size());
        for (const auto &range : local.live_ranges) {
            PePdbLocalLiveRange attached;
            attached.location_kind = static_cast<PePdbLocalLocationKind>(range.location_kind);
            attached.frame_offset = range.frame_offset; attached.register_id = range.register_id;
            attached.offset_in_parent = range.offset_in_parent;
            attached.offset_in_udt = range.offset_in_udt;
            attached.spilled_udt_member = range.spilled_udt_member;
            attached.indirect = range.indirect;
            attached.subfield_register = range.subfield_register;
            attached.may_have_no_name = range.may_have_no_name;
            attached.section = range.section; attached.section_offset = range.section_offset;
            attached.size = range.size; attached.gaps.reserve(range.gaps.size());
            for (const auto &gap : range.gaps) attached.gaps.push_back({gap.offset, gap.size});
            row.live_ranges.push_back(std::move(attached));
        }
        if (local.procedure_section && local.procedure_section <= sections.size() && local.procedure_size) {
            const auto &section = sections[local.procedure_section - 1];
            const auto extent = std::max<std::uint64_t>(section.virtual_size, section.raw_size);
            const auto offset = std::uint64_t{local.procedure_section_offset};
            const auto size = std::uint64_t{local.procedure_size};
            const auto rva = std::uint64_t{section.rva.value} + offset;
            if (offset < extent && size <= extent - offset && rva < image.metadata.image_size &&
                size <= image.metadata.image_size - rva && rva <= std::numeric_limits<std::uint64_t>::max() - base)
                row.procedure_address = Address{image.image->layout().space.id, base + rva};
        }
        output.push_back(std::move(row));
    }
    return output.size();
}

Result<std::size_t> attach_pdb_inline_sites(LoadedImage &image, const types::PdbDatabase &pdb,
                                            const types::PdbLocalTable &locals,
                                            const types::PdbSourceLineTable &lines) {
    if (!image.image || !image.metadata.pe)
        return Error{ErrorCode::unsupported, "PDB inline sites require a loaded PE image"};
    std::size_t matches = 0;
    for (const auto &identity : image.metadata.pe->codeview)
        if (identity.guid == pdb.info.guid && identity.age == pdb.info.age) ++matches;
    if (matches != 1) return std::size_t{0};
    using Key = std::pair<std::uint16_t, std::uint32_t>;
    std::map<Key, const types::PdbInlineeLine *> inlinees;
    std::map<Key, const types::PdbSourceFile *> files;
    std::map<std::uint16_t, std::uint32_t> unsupported_signatures;
    for (const auto &[module, signature] : lines.unsupported_inlinee_signatures)
        unsupported_signatures.emplace(module, signature);
    for (const auto &entry : lines.inlinees)
        if (!inlinees.emplace(Key{entry.module_index, entry.inlinee_id}, &entry).second)
            return Error{ErrorCode::malformed, "Ambiguous inlinee identity during PE binding"};
    for (const auto &file : lines.files)
        if (!files.emplace(Key{file.module_index, file.source_file_id}, &file).second)
            return Error{ErrorCode::malformed, "Ambiguous inline source-file identity during PE binding"};
    const auto base = image.load_base.value_or(image.metadata.preferred_base);
    std::vector<PePdbInlineSite> output;
    std::size_t storage = 0;
    constexpr std::size_t max_storage = 128ull * 1024 * 1024;
    for (const auto &site : locals.inline_sites) {
        PePdbInlineSite row;
        row.module_index = site.module_index; row.section = site.procedure_section;
        row.record_offset = site.record_offset; row.inlinee_id = site.inlinee_id;
        row.depth = site.depth; row.parent_record_offset = site.parent_record_offset;
        row.procedure_name = site.procedure_name; row.unsupported_opcode = site.unsupported_opcode;
        row.annotation_offset = site.annotation_offset;
        row.status = site.unsupported_opcode ? "unsupported annotation opcode " + std::to_string(*site.unsupported_opcode) +
            " at byte " + std::to_string(site.annotation_offset) : "explicit-length ranges";
        if (!site.unsupported_opcode && site.ranges.empty()) row.status = "no explicit-length ranges";
        const auto inlinee = inlinees.find({site.module_index, site.inlinee_id});
        if (inlinee == inlinees.end()) row.status += "; inlinee source identity unavailable";
        if (const auto signature = unsupported_signatures.find(site.module_index); signature != unsupported_signatures.end())
            row.status += "; unsupported InlineeLines signature " + std::to_string(signature->second);
        if (!site.unsupported_opcode) for (const auto &range : site.ranges) {
            PePdbInlineRange attached;
            attached.size = range.size;
            const auto offset = std::uint64_t{site.procedure_offset} + range.code_offset;
            const bool in_procedure = range.code_offset <= site.procedure_size && range.size &&
                range.size <= site.procedure_size - range.code_offset;
            attached.section_offset = offset;
            if (in_procedure && offset <= UINT32_MAX && site.procedure_section &&
                site.procedure_section <= image.metadata.sections.size()) {
                const auto &section = image.metadata.sections[site.procedure_section - 1];
                const auto extent = std::max<std::uint64_t>(section.virtual_size, section.raw_size);
                const auto rva = std::uint64_t{section.rva.value} + offset;
                if (offset < extent && range.size <= extent - offset && rva < image.metadata.image_size &&
                    range.size <= image.metadata.image_size - rva &&
                    rva <= std::numeric_limits<std::uint64_t>::max() - base &&
                    range.size - 1 <= std::numeric_limits<std::uint64_t>::max() - (base + rva))
                    attached.address = Address{image.image->layout().space.id, base + rva};
            }
            if (inlinee != inlinees.end()) {
                const auto file_id = range.source_file_id.value_or(inlinee->second->source_file_id);
                const auto file = files.find({site.module_index, file_id});
                const auto line = static_cast<std::int64_t>(inlinee->second->line) + range.line_delta;
                if (file != files.end() && line > 0 && line <= UINT32_MAX) {
                    attached.source_path = file->second->path;
                    attached.line = static_cast<std::uint32_t>(line);
                } else row.status = "inline source file or line unavailable";
            }
            const auto bytes = sizeof(PePdbInlineRange) + attached.source_path.size();
            if (bytes > max_storage - storage)
                return Error{ErrorCode::resource_limit, "PE inline source output exceeds 128 MiB"};
            storage += bytes;
            row.ranges.push_back(std::move(attached));
        }
        const auto bytes = sizeof(PePdbInlineSite) + row.procedure_name.size() + row.status.size();
        if (bytes > max_storage - storage || output.size() >= 250'000)
            return Error{ErrorCode::resource_limit, "PE inline-site output exceeds limit"};
        storage += bytes;
        output.push_back(std::move(row));
    }
    image.metadata.pe->pdb_inline_sites = std::move(output);
    return image.metadata.pe->pdb_inline_sites.size();
}

Result<bool> bind_local_pe_pdb(LoadedImage &image, const std::filesystem::path &path, std::stop_token stop) {
    if (!image.metadata.pe || !image.image)
        return Error{ErrorCode::unsupported, "PDB binding requires a loaded PE image"};
    auto &pe = *image.metadata.pe;
    pe.pdb_path = path.u8string().empty() ? std::string{} : [&] {
        const auto value = path.u8string();
        return std::string(reinterpret_cast<const char *>(value.data()), value.size());
    }();
    pe.pdb_status = PePdbStatus::malformed;
    pe.pdb_symbols.clear(); pe.pdb_types.clear(); pe.pdb_locals.clear(); pe.source_lines.clear();
    pe.pdb_inline_sites.clear();
    auto file = FileStorage::open(path);
    if (!file) {
        if (file.error().code == ErrorCode::io) { pe.pdb_status = PePdbStatus::missing; return false; }
        return file.error();
    }
    constexpr std::uint64_t max_pdb_bytes = 512ull * 1024 * 1024;
    if (file.value()->size() == 0 || file.value()->size() > max_pdb_bytes) {
        pe.pdb_status = PePdbStatus::malformed;
        image.diagnostics.push_back({DiagnosticSeverity::warning, "Local PDB is empty or exceeds the 512 MiB import limit", {}});
        return false;
    }
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "PDB binding canceled"};
    auto view = file.value()->read_at({0}, static_cast<std::size_t>(file.value()->size()));
    if (!view) { pe.pdb_status = PePdbStatus::malformed; return false; }
    auto database = types::parse_pdb(view.value().bytes, stop);
    if (!database) {
        if (database.error().code == ErrorCode::canceled) return database.error();
        pe.pdb_status = PePdbStatus::malformed;
        image.diagnostics.push_back({DiagnosticSeverity::warning, "Local PDB could not be parsed: " + database.error().message, {}});
        return false;
    }
    std::size_t matches = 0;
    for (const auto &identity : pe.codeview)
        if (identity.guid == database.value().info.guid && identity.age == database.value().info.age) ++matches;
    if (matches != 1) {
        pe.pdb_status = PePdbStatus::mismatch;
        image.diagnostics.push_back({DiagnosticSeverity::warning,
            matches == 0 ? "Local PDB GUID+age does not match the PE CodeView identity" :
                           "PE has ambiguous duplicate CodeView identities; PDB was not bound", {}});
        return false;
    }
    auto lines = types::parse_pdb_source_lines(database.value(), stop);
    auto symbols = types::parse_pdb_symbols(database.value(), stop);
    auto locals = types::parse_pdb_locals(database.value(), stop);
    auto type_stream = types::parse_pdb_types(database.value(), stop);
    const auto base = image.load_base.value_or(image.metadata.preferred_base);
    auto partial_warning = [&](std::string_view stream, const Error &error) {
        if (error.code == ErrorCode::canceled) return false;
        image.diagnostics.push_back({DiagnosticSeverity::warning,
            "Matching PDB " + std::string(stream) + " stream unavailable: " + error.message, {}});
        return true;
    };
    if (lines) {
        auto attached = attach_pdb_source_lines(image, database.value(), lines.value());
        if (!attached) return attached.error();
    } else {
        if (!partial_warning("C13 line", lines.error())) return lines.error();
    }
    if (locals) {
        const types::PdbSourceLineTable no_lines;
        auto attached = attach_pdb_inline_sites(image, database.value(), locals.value(), lines ? lines.value() : no_lines);
        if (!attached && !partial_warning("inline site", attached.error())) return attached.error();
    }
    if (symbols) {
        for (const auto &symbol : symbols.value().symbols) {
            PePdbSymbol row{symbol.name, symbol.kind == types::PdbSymbolKind::procedure, symbol.section,
                            symbol.section_offset, symbol.size, {}, symbol.module_name, symbol.object_name,
                            symbol.public_symbol,
                            symbol.source == types::PdbSymbolSource::global_stream};
            row.frame_size = symbol.frame_size;
            row.frame_padding_size = symbol.frame_padding_size;
            row.frame_padding_offset = symbol.frame_padding_offset;
            row.callee_saved_register_bytes = symbol.callee_saved_register_bytes;
            row.exception_handler_offset = symbol.exception_handler_offset;
            row.exception_handler_section = symbol.exception_handler_section;
            row.frame_flags = symbol.frame_flags;
            row.has_frame_data = symbol.has_frame_data;
            row.type_index = symbol.type_index;
            row.type_index_is_id = symbol.type_index_is_id;
            if (symbol.section != 0 && symbol.section <= image.metadata.sections.size()) {
                const auto &section = image.metadata.sections[symbol.section - 1];
                const auto extent = std::max<std::uint64_t>(section.virtual_size, section.raw_size);
                const auto offset = std::uint64_t{symbol.section_offset};
                const auto size = row.procedure ? std::uint64_t{row.size} : 1;
                const auto rva = std::uint64_t{section.rva.value} + offset;
                if (offset < extent && size <= extent - offset && rva < image.metadata.image_size &&
                    size <= image.metadata.image_size - rva && rva <= std::numeric_limits<std::uint64_t>::max() - base)
                    row.address = Address{image.image->layout().space.id, base + rva};
            }
            pe.pdb_symbols.push_back(std::move(row));
        }
    } else {
        if (!partial_warning("DBI symbol", symbols.error())) return symbols.error();
    }
    if (locals) {
        auto attached = attach_pdb_locals(image, database.value(), locals.value());
        if (!attached) return attached.error();
    } else {
        if (!partial_warning("DBI local", locals.error())) return locals.error();
    }
    if (type_stream) {
        auto graph = types::resolve_pdb_type_graph(type_stream.value(), stop);
        if (!graph && graph.error().code == ErrorCode::canceled) return graph.error();
        const auto graph_field_list_complete = [&](const types::PdbTypeGraph &resolved,
                                                   const types::CodeViewTypeRecord &record) {
            if ((record.kind != types::CodeViewTypeKind::structure &&
                 record.kind != types::CodeViewTypeKind::class_type) || record.forward_declaration)
                return false;
            if (!record.field_list) return true;
            std::vector<std::uint32_t> pending;
            std::vector<std::uint32_t> seen;
            std::size_t roots = 0;
            for (const auto &reference : resolved.references) {
                if (reference.source_index != record.index ||
                    reference.kind != types::PdbTypeReferenceKind::field_list) continue;
                ++roots;
                if (!reference.resolved) return false;
                pending.push_back(reference.target_index);
            }
            if (roots != 1) return false;
            while (!pending.empty()) {
                const auto index = pending.back(); pending.pop_back();
                if (std::find(seen.begin(), seen.end(), index) != seen.end()) return false;
                seen.push_back(index);
                bool found_list = false;
                for (const auto &reference : resolved.references) {
                    if (reference.source_index != index ||
                        reference.kind != types::PdbTypeReferenceKind::field_list_continuation) continue;
                    if (!reference.resolved) return false;
                    pending.push_back(reference.target_index);
                }
                for (const auto &node : resolved.nodes)
                    if (node.record.index == index && node.record.kind == types::CodeViewTypeKind::field_list) {
                        found_list = true;
                        break;
                    }
                if (!found_list) return false;
            }
            return true;
        };
        for (const auto &record : type_stream.value().records) {
            if (record.kind == types::CodeViewTypeKind::unsupported) continue;
            PePdbType attached;
            attached.index = record.index;
            attached.name = record.name;
            attached.leaf = record.leaf;
            attached.size = record.size;
            attached.fields.reserve(record.fields.size());
            for (const auto &field : record.fields)
                attached.fields.push_back({field.leaf, field.type, field.offset});
            if (graph) {
                const auto node = std::find_if(graph.value().nodes.begin(), graph.value().nodes.end(),
                    [&](const auto &candidate) { return candidate.record.index == record.index; });
                if (node != graph.value().nodes.end() && graph_field_list_complete(graph.value(), record)) {
                    attached.fields.clear();
                    constexpr std::size_t max_retained_fields = 4096;
                    const auto retained = std::min(node->expanded_fields.size(), max_retained_fields);
                    attached.fields.reserve(retained);
                    for (std::size_t i = 0; i < retained; ++i) {
                        const auto &field = node->expanded_fields[i];
                        attached.fields.push_back({field.leaf, field.type, field.offset});
                    }
                    attached.field_layout_complete = node->expanded_fields.size() <= max_retained_fields;
                }
            }
            pe.pdb_types.push_back(std::move(attached));
        }
    } else {
        if (!partial_warning("TPI type", type_stream.error())) return type_stream.error();
    }
    pe.pdb_status = PePdbStatus::matched;
    return true;
}
} // namespace hexlab
