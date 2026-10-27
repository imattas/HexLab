#pragma once
#include "hexlab/image/metadata.hpp"
#include "demangle_output.hpp"
#include <algorithm>
#include <ostream>
#include <string_view>

namespace hexlab::cli {
inline std::string escape_pe_version_text(std::string_view value) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size());
    for (const unsigned char ch : value) {
        switch (ch) {
        case '\\': result += "\\\\"; break;
        case '"': result += "\\\""; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (ch < 0x20 || ch == 0x7f) {
                result += "\\x";
                result.push_back(hex[ch >> 4]);
                result.push_back(hex[ch & 0xf]);
            } else result.push_back(static_cast<char>(ch));
        }
    }
    return result;
}
inline void pe_description(std::ostream &out, const ImageMetadata &metadata) {
    if (metadata.format != "PE" && metadata.format != "PE32" && metadata.format != "PE32+")
        return;
    out << "PE directories:\n";
    const auto directory_count = std::min<std::size_t>(metadata.directories.size(), 16);
    for (std::size_t i = 0; i < directory_count; ++i) {
        const auto &directory = metadata.directories[i];
        out << "  #" << directory.index << " " << (directory.file_offset ? "file:" : "rva:")
            << "0x" << std::hex << directory.location << " size=0x" << directory.size << std::dec << '\n';
    }
    if (metadata.pe) {
        if (metadata.pe->global_pointer_rva) {
            out << "PE global pointer: RVA=0x" << std::hex << *metadata.pe->global_pointer_rva
                << " VA=0x" << (metadata.preferred_base + *metadata.pe->global_pointer_rva)
                << std::dec << '\n';
        }
        if (!metadata.pe->coff_symbols.empty()) {
            constexpr std::size_t coff_symbol_output_limit = 4096;
            out << "PE COFF symbols: " << metadata.pe->coff_symbols.size() << '\n';
            const auto shown=std::min(coff_symbol_output_limit,metadata.pe->coff_symbols.size());
            for(std::size_t i=0;i<shown;++i){
                const auto &symbol=metadata.pe->coff_symbols[i];
                out<<"  #"<<symbol.table_index<<" "<<symbol.name<<" section="<<symbol.section_number
                   <<" value=0x"<<std::hex<<symbol.value<<std::dec<<" class="<<unsigned(symbol.storage_class)
                   <<" aux="<<unsigned(symbol.auxiliary_count)<<" file=0x"<<std::hex<<symbol.source_file_offset.value<<std::dec;
                if(symbol.address)out<<" VA=0x"<<std::hex<<symbol.address->offset<<std::dec;
                out<<'\n';
            }
            if(shown<metadata.pe->coff_symbols.size())out<<"  output limited to 4096 rows\n";
        }
        const auto render_version = [](const std::array<std::uint16_t, 4> &version) {
            return std::to_string(version[0]) + "." + std::to_string(version[1]) + "." +
                   std::to_string(version[2]) + "." + std::to_string(version[3]);
        };
        std::size_t emitted_versions = 0;
        std::size_t emitted_version_strings = 0;
        for (const auto &resource : metadata.pe->resources) {
            if (!resource.version_info) continue;
            if (emitted_versions == 256) {
                out << "PE version resources: output limited to 256 rows\n";
                break;
            }
            out << "PE version resource name=";
            if (resource.name.name) out << *resource.name.name;
            else if (resource.name.id) out << *resource.name.id;
            else out << "?";
            out << " file=" << render_version(resource.version_info->file_version)
                << " product=" << render_version(resource.version_info->product_version);
            if (!resource.version_info->fixed_info.spans.empty())
                out << " file:0x" << std::hex << resource.version_info->fixed_info.spans.front().offset.value << std::dec;
            out << '\n';
            for (const auto &entry : resource.version_info->strings) {
                if (emitted_version_strings == 4096) {
                    out << "PE version strings: output limited to 4096 entries\n";
                    break;
                }
                out << "  PE version string lang=0x" << std::hex << entry.language
                    << " codepage=0x" << entry.code_page << std::dec << " \""
                    << escape_pe_version_text(entry.key) << "\"=\""
                    << escape_pe_version_text(entry.value) << "\"\n";
                ++emitted_version_strings;
            }
            if (!resource.version_info->string_tables_complete)
                out << "  PE version string tables: incomplete or exceeded bounded inspection budget\n";
            ++emitted_versions;
        }
        std::size_t emitted_manifests = 0, emitted_manifest_dependencies = 0;
        for (const auto &resource : metadata.pe->resources) {
            if (!resource.manifest_info) continue;
            if (emitted_manifests == 256) {
                out << "PE manifest resources: output limited to 256 rows\n";
                break;
            }
            const auto &manifest = *resource.manifest_info;
            out << "PE manifest resource name=";
            if (resource.name.name) out << *resource.name.name;
            else if (resource.name.id) out << *resource.name.id;
            else out << "?";
            if (!manifest.complete) out << " (partial)";
            if (!manifest.source.spans.empty())
                out << " file:0x" << std::hex << manifest.source.spans.front().offset.value << std::dec;
            out << '\n';
            const auto identity = [&](const char *label, const PeManifestAssemblyIdentity &value) {
                out << "  " << label;
                const auto attr = [&](const char *key, const std::optional<std::string> &field) {
                    if (field) out << ' ' << key << "=\"" << escape_pe_version_text(*field) << '"';
                };
                attr("name", value.name); attr("version", value.version); attr("type", value.type);
                attr("processorArchitecture", value.processor_architecture);
                attr("publicKeyToken", value.public_key_token); attr("language", value.language);
                out << '\n';
            };
            if (manifest.application_identity) identity("identity", *manifest.application_identity);
            if (manifest.requested_execution_level) {
                out << "  requestedExecutionLevel=\""
                    << escape_pe_version_text(*manifest.requested_execution_level) << '"';
                if (manifest.ui_access) out << " uiAccess=\"" << (*manifest.ui_access ? "true" : "false") << '"';
                out << '\n';
            }
            for (const auto &dependency : manifest.dependencies) {
                if (emitted_manifest_dependencies == 4096) {
                    out << "  PE manifest dependencies: output limited to 4096 rows\n";
                    break;
                }
                identity("dependency", dependency);
                ++emitted_manifest_dependencies;
            }
            ++emitted_manifests;
        }
    }
    if (metadata.pe && (!metadata.pe->exception_functions.empty() ||
                        !metadata.pe->arm64_exception_functions.empty())) {
        constexpr std::size_t pe_exception_output_limit = 1024;
        std::size_t emitted = 0;
        const auto source_offset = [](const PeRecordSource &source) -> std::optional<std::uint64_t> {
            if (source.spans.empty()) return {};
            return source.spans.front().offset.value;
        };
        out << "PE exception metadata: AMD64=" << metadata.pe->exception_functions.size()
            << " ARM64=" << metadata.pe->arm64_exception_functions.size() << '\n';
        const auto emit_source = [&](const PeRecordSource &source) {
            if (const auto offset = source_offset(source))
                out << " file=0x" << std::hex << *offset << std::dec;
        };
        for (const auto &function : metadata.pe->exception_functions) {
            if (emitted >= pe_exception_output_limit) break;
            out << "  AMD64 function RVA=0x" << std::hex << function.begin_rva
                << "..0x" << function.end_rva << " unwind=0x" << function.unwind_info_rva << std::dec;
            emit_source(function.source);
            out << '\n';
            ++emitted;
            if (!function.unwind_info || !function.unwind_info->handler_payload) continue;
            const auto &payload = *function.unwind_info->handler_payload;
            const char *status = payload.status == PeHandlerPayloadStatus::decoded_c_specific_scope_table
                ? "C scope table" : payload.status == PeHandlerPayloadStatus::decoded_cxx_func_info
                ? "FH3 FuncInfo" : payload.status == PeHandlerPayloadStatus::decoded_cxx_func_info4
                ? "FH4 FuncInfo" : payload.status == PeHandlerPayloadStatus::unsupported_handler
                ? "unsupported handler" : "unresolved handler";
            if (emitted >= pe_exception_output_limit) break;
            out << "    " << status;
            if (payload.handler_name) out << " handler=" << *payload.handler_name;
            out << " payload=0x" << std::hex << payload.payload_rva << std::dec;
            if (payload.source) emit_source(*payload.source);
            out << '\n';
            ++emitted;
            if (payload.cxx_func_info) {
                const auto &info = *payload.cxx_func_info;
                if (emitted < pe_exception_output_limit) {
                    out << "      FH3 states=" << info.max_state << " try-blocks=" << info.try_blocks.size()
                        << " IP-states=" << info.ip_to_state.size();
                    if (info.exception_spec_types)
                        out << " exception-spec-types=" << info.exception_spec_types->types.size();
                    emit_source(info.source);
                    out << '\n';
                    ++emitted;
                }
                for (std::size_t state = 0; state < info.unwind_map.size(); ++state) {
                    if (emitted >= pe_exception_output_limit) break;
                    const auto &entry = info.unwind_map[state];
                    out << "        FH3 unwind state=" << state << " to=" << entry.to_state;
                    if (entry.action_rva) out << " action=0x" << std::hex << entry.action_rva << std::dec;
                    emit_source(entry.source);
                    out << '\n';
                    ++emitted;
                }
                for (const auto &entry : info.ip_to_state) {
                    if (emitted >= pe_exception_output_limit) break;
                    out << "        FH3 IP-state RVA=0x" << std::hex << entry.ip_rva << std::dec
                        << " state=" << entry.state;
                    emit_source(entry.source);
                    out << '\n';
                    ++emitted;
                }
                for (const auto &block : info.try_blocks) {
                    if (emitted >= pe_exception_output_limit) break;
                    out << "        FH3 try states=" << block.try_low << ".." << block.try_high
                        << " catch-high=" << block.catch_high << " handlers=" << block.handlers.size();
                    emit_source(block.source);
                    out << '\n';
                    ++emitted;
                    for (const auto &handler : block.handlers) {
                        if (emitted >= pe_exception_output_limit) break;
                        out << "          FH3 handler="
                            << handler.decorated_type_name.value_or("<catch-all/unknown>")
                            << " adjectives=0x" << std::hex << handler.adjectives
                            << " target=0x" << handler.handler_rva << std::dec
                            << " object-offset=" << handler.catch_object_offset
                            << " frame-offset=" << handler.frame_offset;
                        emit_source(handler.source);
                        if (handler.type_descriptor_source) emit_source(*handler.type_descriptor_source);
                        out << '\n';
                        ++emitted;
                    }
                }
                if (info.exception_spec_types && emitted < pe_exception_output_limit) {
                    const auto &list = *info.exception_spec_types;
                    out << "        FH3 exception specification count=" << list.count
                        << " types=" << list.types.size() << " array-rva=0x" << std::hex
                        << list.type_array_rva << std::dec;
                    emit_source(list.source);
                    out << '\n';
                    ++emitted;
                    for (const auto &type : list.types) {
                        if (emitted >= pe_exception_output_limit) break;
                        out << "          type=" << type.decorated_type_name.value_or("<unknown>")
                            << " adjectives=0x" << std::hex << type.adjectives << std::dec;
                        emit_source(type.source);
                        if (type.type_descriptor_source) emit_source(*type.type_descriptor_source);
                        out << '\n';
                        ++emitted;
                    }
                }
            }
            if (payload.cxx_func_info4) {
                const auto &info = *payload.cxx_func_info4;
                if (emitted < pe_exception_output_limit) {
                    const char *fh4_status = info.status == PeCxxFuncInfo4Status::decoded_subset
                        ? "decoded-subset" : info.status == PeCxxFuncInfo4Status::malformed
                        ? "malformed" : "unsupported";
                    out << "      FH4 " << fh4_status << " header=0x" << std::hex
                        << static_cast<unsigned>(info.header) << " IP-map=0x" << info.ip_map_rva
                        << std::dec << " IP-states=" << info.ip_to_state.size()
                        << " unwind-rows=" << info.unwind_map.size()
                        << " try-blocks=" << info.try_blocks.size()
                        << " catch-funclet=" << (info.is_catch_funclet ? "yes" : "no")
                        << " noexcept=" << (info.is_noexcept ? "yes" : "no");
                    if (!info.diagnostic.empty()) out << " diagnostic=" << info.diagnostic;
                    emit_source(info.source);
                    out << '\n';
                    ++emitted;
                }
                for (const auto &entry : info.unwind_map) {
                    if (emitted >= pe_exception_output_limit) break;
                    out << "        FH4 unwind type=" << static_cast<unsigned>(entry.type)
                        << " previous=";
                    if (entry.previous_entry_index) out << *entry.previous_entry_index;
                    else out << "none";
                    if (entry.action_rva) out << " action=0x" << std::hex << *entry.action_rva << std::dec;
                    if (entry.object_offset) out << " object-offset=0x" << std::hex << *entry.object_offset << std::dec;
                    emit_source(entry.source);
                    out << '\n';
                    ++emitted;
                }
                for (const auto &block : info.try_blocks) {
                    if (emitted >= pe_exception_output_limit) break;
                    out << "        FH4 try states=" << block.try_low << ".." << block.try_high
                        << " catch-high=" << block.catch_high << " handlers=" << block.handlers.size();
                    emit_source(block.source);
                    out << '\n';
                    ++emitted;
                    for (const auto &handler : block.handlers) {
                        if (emitted >= pe_exception_output_limit) break;
                        out << "          FH4 handler=" << handler.decorated_type_name.value_or("<catch-all/unknown>")
                            << " target=0x" << std::hex << handler.handler_rva << std::dec;
                        if (handler.catch_object_offset)
                            out << " object-offset=0x" << std::hex << *handler.catch_object_offset << std::dec;
                        out << " continuations=" << handler.continuation_addresses.size();
                        emit_source(handler.source);
                        out << '\n';
                        ++emitted;
                    }
                }
            }
        }
        for (const auto &function : metadata.pe->arm64_exception_functions) {
            if (emitted >= pe_exception_output_limit) break;
            const char *kind = function.kind == PeArm64UnwindKind::xdata ? "xdata" :
                               function.kind == PeArm64UnwindKind::packed_single ? "packed-single" :
                               function.kind == PeArm64UnwindKind::packed_fragment ? "packed-fragment" : "pdata-link";
            out << "  ARM64 " << kind << " function RVA=0x" << std::hex << function.begin_rva
                << " length=0x" << function.function_length << std::dec;
            if (function.linked_record_rva)
                out << " parent=0x" << std::hex << *function.linked_record_rva << std::dec;
            emit_source(function.source);
            out << '\n';
            ++emitted;
        }
        if (emitted >= pe_exception_output_limit)
            out << "  ... exception metadata output limited to " << pe_exception_output_limit << " rows\n";
    }
    if (metadata.pe && metadata.pe->tls) {
        const auto &tls = *metadata.pe->tls;
        out << "PE TLS: template-start-RVA=0x" << std::hex << tls.template_rva
            << " template-end-RVA=0x" << (tls.template_rva + tls.template_size)
            << " index-RVA=0x" << tls.index_rva
            << " callbacks-RVA=0x" << tls.callbacks_rva
            << " zero-fill=0x" << tls.zero_fill
            << " characteristics=0x" << tls.characteristics << std::dec
            << " callbacks=" << tls.callbacks.size() << '\n';
        constexpr std::size_t tls_callback_output_limit = 4096;
        const auto callback_count = std::min(tls.callbacks.size(), tls_callback_output_limit);
        for (std::size_t i = 0; i < callback_count; ++i) {
            const auto &callback = tls.callbacks[i];
            out << "  callback[" << i << "] RVA=0x" << std::hex << callback.rva
                << " VA=0x" << (metadata.preferred_base + callback.rva) << std::dec;
            if (!callback.source.spans.empty())
                out << " file=0x" << std::hex << callback.source.spans.front().offset.value << std::dec;
            out << '\n';
        }
        if (callback_count != tls.callbacks.size())
            out << "  ... TLS callback output limited to " << tls_callback_output_limit << " rows\n";
        if (tls.callback_terminator && !tls.callback_terminator->spans.empty())
            out << "  callback terminator file=0x" << std::hex
                << tls.callback_terminator->spans.front().offset.value << std::dec << '\n';
    }
    if (metadata.pe && metadata.pe->load_configuration) {
        const auto &config = *metadata.pe->load_configuration;
        out << "PE load configuration: size=0x" << std::hex << config.declared_size
            << " timestamp=0x" << config.timestamp << " version=" << std::dec
            << config.major_version << '.' << config.minor_version
            << " guard-flags=0x" << std::hex << config.guard_flags << std::dec << '\n';
        const auto pointer = [&](const char *name, std::optional<std::uint64_t> rva) {
            if (rva) out << "  " << name << " RVA=0x" << std::hex << *rva << std::dec << '\n';
        };
        pointer("Security cookie", config.security_cookie_rva);
        pointer("Guard CF check", config.guard_check_rva);
        pointer("Guard CF dispatch", config.guard_dispatch_rva);
        pointer("Guard CF function table", config.guard_function_table_rva);
        pointer("Guard address-taken IAT table", config.guard_address_taken_iat_table_rva);
        pointer("Guard long-jump table", config.guard_long_jump_table_rva);
        pointer("Guard EH-continuation table", config.guard_eh_continuation_table_rva);
        pointer("Guard XFG check", config.guard_xfg_check_rva);
        pointer("Guard XFG dispatch", config.guard_xfg_dispatch_rva);
        pointer("Guard XFG table dispatch", config.guard_xfg_table_dispatch_rva);
        pointer("CastGuard failure mode", config.cast_guard_failure_mode_rva);
        pointer("Guard memcpy", config.guard_memcpy_rva);
        pointer("Guard RF failure routine", config.guard_rf_failure_routine_rva);
        pointer("Guard RF failure routine function pointer", config.guard_rf_failure_routine_pointer_rva);
        pointer("Guard RF verify stack function pointer", config.guard_rf_verify_stack_pointer_rva);
        pointer("Enclave configuration", config.enclave_configuration_rva);
        pointer("Volatile metadata", config.volatile_metadata_rva);
        if (config.hot_patch_table_offset)
            out << "  Hot-patch table offset=0x" << std::hex << *config.hot_patch_table_offset << std::dec << '\n';
        auto table = [&](const char *name, const auto &targets) {
            if (targets.empty()) return;
            out << "  " << name << ": " << targets.size() << " entries\n";
            const auto count = std::min<std::size_t>(targets.size(), 4096);
            for (std::size_t index = 0; index < count; ++index) {
                const auto &target = targets[index];
                out << "    RVA=0x" << std::hex << target.rva << std::dec;
                if constexpr (requires { target.flags; }) {
                    if (target.flags) {
                        out << " gfids-flags=0x" << std::hex << unsigned(*target.flags) << std::dec;
                        if ((*target.flags & 0x1u) != 0) out << " fid-suppressed";
                        if ((*target.flags & 0x2u) != 0) out << " export-suppressed";
                    }
                }
                if (!target.source.spans.empty())
                    out << " file=0x" << std::hex << target.source.spans.front().offset.value << std::dec;
                out << '\n';
            }
            if (count != targets.size()) out << "    ... output limited to 4096 rows\n";
        };
        table("Guard CF function targets", config.guard_functions);
        table("Guard address-taken IAT", config.guard_address_taken_iat_entries);
        table("Guard long-jump targets", config.guard_long_jump_targets);
        table("Guard EH-continuation targets", config.guard_eh_continuation_targets);
        if (config.dynamic_value_relocations) {
            const auto &dynamic = *config.dynamic_value_relocations;
            const auto status = dynamic.status == PeDynamicRelocationStatus::decoded_layout ? "decoded" :
                                dynamic.status == PeDynamicRelocationStatus::unsupported ? "unsupported" : "malformed";
            const auto application = dynamic.application_status == PeDynamicRelocationApplicationStatus::applied ? "applied" :
                                     dynamic.application_status == PeDynamicRelocationApplicationStatus::unsupported ? "unsupported" :
                                     dynamic.application_status == PeDynamicRelocationApplicationStatus::conflict ? "conflict" :
                                     dynamic.application_status == PeDynamicRelocationApplicationStatus::malformed ? "not-applied" :
                                     "not-attempted";
            out << "PE dynamic value relocations: v" << dynamic.version << " status=" << status
                << " records=" << dynamic.records.size() << " application=" << application
                << " applied-fixups=" << dynamic.applied_fixups.size() << '\n';
            if (!dynamic.application_diagnostic.empty())
                out << "  application: " << dynamic.application_diagnostic << '\n';
            std::size_t emitted = 0;
            for (const auto &record : dynamic.records) {
                if (emitted >= 4096) { out << "  ... dynamic relocation output limited to 4096 rows\n"; break; }
                out << "  symbol=0x" << std::hex << record.symbol << std::dec;
                if (dynamic.version == 2)
                    out << " group=0x" << std::hex << record.symbol_group << " flags=0x" << record.flags << std::dec;
                out << " fixup-bytes=0x" << std::hex << record.fixup_size << std::dec
                    << " fixups=" << (record.fixups_decoded ? std::to_string(record.fixups.size()) : "opaque")
                    << " " << record.diagnostic << '\n';
                ++emitted;
                for (const auto &fixup : record.fixups) {
                    if (emitted >= 4096) { out << "  ... dynamic relocation output limited to 4096 rows\n"; break; }
                    const auto kind = fixup.kind == PeDynamicRelocationFixupKind::zero_fill ? "zero-fill" :
                                      fixup.kind == PeDynamicRelocationFixupKind::value ? "value" : "delta";
                    out << "    " << kind << " RVA=0x" << std::hex << fixup.rva << " size=0x"
                        << static_cast<unsigned>(fixup.size) << std::dec;
                    if (fixup.delta) out << " delta=" << *fixup.delta;
                    if (!fixup.value.empty()) {
                        out << " value=";
                        for (const auto byte : fixup.value)
                            out << std::hex << (std::to_integer<unsigned>(byte) >> 4)
                                << (std::to_integer<unsigned>(byte) & 15u);
                        out << std::dec;
                    }
                    if (!fixup.source.spans.empty())
                        out << " fixup-file=0x" << std::hex << fixup.source.spans.front().offset.value << std::dec;
                    out << '\n';
                    ++emitted;
                }
            }
        }
        if (config.chpe_metadata) {
            const auto &chpe = *config.chpe_metadata;
            out << "PE CHPE metadata: v" << chpe.version << " RVA=0x" << std::hex
                << chpe.metadata_rva << " code-map=0x" << chpe.code_map_rva << std::dec
                << " ranges=" << chpe.code_ranges.size() << '\n';
            const auto count = std::min<std::size_t>(chpe.code_ranges.size(), 4096);
            for (std::size_t i = 0; i < count; ++i) {
                const auto &range = chpe.code_ranges[i];
                const char *kind = range.kind == PeChpeCodeRangeKind::arm64 ? "ARM64" :
                                   range.kind == PeChpeCodeRangeKind::arm64ec ? "ARM64EC" : "AMD64";
                out << "  " << kind << " RVA=0x" << std::hex << range.start_rva
                    << " length=0x" << range.length << std::dec;
                if (!range.source.spans.empty())
                    out << " file=0x" << std::hex << range.source.spans.front().offset.value << std::dec;
                out << '\n';
            }
            if (count != chpe.code_ranges.size())
                out << "  ... CHPE range output limited to 4096 rows\n";
            out << "  validated per-range decode contexts are retained in the image execution profile\n";
        }
    }
    if (metadata.pe && !metadata.pe->bound_imports.empty()) {
        out << "PE bound imports:\n";
        std::size_t emitted = 0;
        for (const auto &item : metadata.pe->bound_imports) {
            if (emitted >= 4096) break;
            out << "  " << item.library << " timestamp=0x" << std::hex << item.timestamp << std::dec;
            if (!item.descriptor.spans.empty()) out << " file:0x" << std::hex << item.descriptor.spans.front().offset.value << std::dec;
            out << '\n';
            ++emitted;
            for (const auto &forwarder : item.forwarders) {
                if (emitted >= 4096) break;
                out << "    -> " << forwarder.library << " timestamp=0x" << std::hex << forwarder.timestamp << std::dec;
                if (!forwarder.descriptor.spans.empty()) out << " file:0x" << std::hex << forwarder.descriptor.spans.front().offset.value << std::dec;
                out << '\n';
                ++emitted;
            }
        }
    }
    if (metadata.pe && !metadata.pe->pogo_data.empty()) {
        std::size_t emitted = 0, payloads_printed = 0;
        out << "PE POGO profile records: " << metadata.pe->pogo_data.size() << " payloads\n";
        for (const auto &payload : metadata.pe->pogo_data) {
            if (payloads_printed >= 4096) break;
            ++payloads_printed;
            const char *signature = payload.signature == 0x4c544347u ? "LTCG" : "PGU";
            out << "  signature=" << signature << " entries=" << payload.entries.size() << '\n';
            for (const auto &record : payload.entries) {
                if (emitted >= 4096) break;
                out << "    RVA=0x" << std::hex << record.rva << " size=0x" << record.size << std::dec
                    << " name=\"" << escape_pe_version_text(record.name) << '\"';
                if (!record.source.spans.empty())
                    out << " file=0x" << std::hex << record.source.spans.front().offset.value << std::dec;
                out << '\n';
                ++emitted;
            }
            if (emitted >= 4096) break;
        }
        std::size_t total = 0;
        for (const auto &payload : metadata.pe->pogo_data) total += payload.entries.size();
        if (emitted < total) out << "  POGO entry output limited to 4096 rows; omitted=" << total - emitted << '\n';
        if (payloads_printed < metadata.pe->pogo_data.size())
            out << "  POGO payload output limited to 4096 rows; omitted="
                << metadata.pe->pogo_data.size() - payloads_printed << '\n';
    }
    if (metadata.pe && metadata.pe->pdb_status != PePdbStatus::unavailable) {
        const auto status = metadata.pe->pdb_status == PePdbStatus::matched ? "matched" :
                            metadata.pe->pdb_status == PePdbStatus::missing ? "missing" :
                            metadata.pe->pdb_status == PePdbStatus::mismatch ? "identity mismatch" : "malformed";
        out << "PE PDB: " << status;
        if (!metadata.pe->pdb_path.empty()) out << " path=" << metadata.pe->pdb_path;
        out << " symbols=" << metadata.pe->pdb_symbols.size() << " types=" << metadata.pe->pdb_types.size()
            << " source-lines=" << metadata.pe->source_lines.size() << '\n';
        std::size_t emitted = 0;
        for (const auto &symbol : metadata.pe->pdb_symbols) {
            if (emitted++ == 256) { out << "  ... symbol output limited to 256 rows\n"; break; }
            out << "  " << (symbol.procedure ? "procedure " : "data ") << symbol.name;
            if (auto rendered = demangled_name(symbol.name); !rendered.empty()) out << " [" << rendered << ']';
            if (symbol.address) out << " VA=0x" << std::hex << symbol.address->offset << std::dec;
            else out << " section=" << symbol.section << "+0x" << std::hex << symbol.section_offset << std::dec;
            if (symbol.type_index)
                out << " type=" << (symbol.type_index_is_id ? "IPI" : "TPI") << ":0x" << std::hex
                    << symbol.type_index << std::dec;
            out << '\n';
        }
    }
}
} // namespace hexlab::cli
