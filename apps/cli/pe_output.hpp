#pragma once
#include "hexlab/image/metadata.hpp"
#include "hexlab/loaders/pe.hpp"
#include "demangle_output.hpp"
#include <algorithm>
#include <iomanip>
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
inline void pe_description(std::ostream &out, const ImageMetadata &metadata, const Image *image = nullptr) {
    if (metadata.format != "PE" && metadata.format != "PE32" && metadata.format != "PE32+")
        return;
    if (image && image->storage()) {
        const auto rich = inspect_pe_rich_header(*image->storage());
        if (!rich) {
            out << "PE Rich header: unavailable (" << rich.error().message << ")\n";
        } else if (rich.value()) {
            const auto &header = *rich.value();
            out << "PE Rich header: file-offset=0x" << std::hex << header.source_file_offset.value
                << " size=0x" << header.byte_size << " xor-key=0x" << header.xor_key << std::dec
                << " records=" << header.records.size() << '\n';
            constexpr std::size_t rich_cli_record_limit = 128;
            for (std::size_t index = 0; index < (std::min)(header.records.size(), rich_cli_record_limit); ++index) {
                const auto &record = header.records[index];
                out << "  Rich[" << index << "]: product=0x" << std::hex << (record.comp_id >> 16)
                    << " build=0x" << (record.comp_id & 0xffffu) << std::dec
                    << " count=" << record.count << '\n';
            }
            if (header.records.size() > rich_cli_record_limit)
                out << "  Rich records truncated at " << rich_cli_record_limit << '\n';
        }
    }
    if (metadata.pe && metadata.pe->image_checksum) {
        const auto &checksum = *metadata.pe->image_checksum;
        const auto status = checksum.status == PeImageChecksumStatus::matches ? "matches" :
            checksum.status == PeImageChecksumStatus::mismatch ? "mismatch" :
            checksum.status == PeImageChecksumStatus::unset ? "unset" : "not-checked-limit";
        out << "PE checksum: stored=0x" << std::hex << checksum.stored << std::dec
            << " status=" << status << " file-size=" << checksum.file_size
            << " checksum-field-file-offset=0x" << std::hex << checksum.source_file_offset.value << std::dec;
        if (checksum.computed) out << " computed=0x" << std::hex << *checksum.computed << std::dec;
        out << '\n';
    }
    if (image) {
        const auto profile = image->storage()
            ? analyze_pe_sections(*image->storage(), metadata)
            : Result<std::vector<PeSectionProfile>>(Error{ErrorCode::invalid_argument, "image storage unavailable"});
        if (profile) {
            out << "PE section profile:\n";
            for (const auto &section : profile.value()) {
                out << "  " << section.name << " RVA=0x" << std::hex << section.rva.value
                    << " raw=0x" << section.raw_size << " virtual=0x" << section.virtual_size
                    << std::dec << " entropy=" << std::fixed << std::setprecision(3)
                    << section.entropy_bits_per_byte << " bits/byte permissions="
                    << (section.readable ? 'r' : '-') << (section.writable ? 'w' : '-')
                    << (section.executable ? 'x' : '-') << std::defaultfloat << '\n';
            }
        } else {
            out << "PE section profile: unavailable (" << escape_pe_version_text(profile.error().message) << ")\n";
        }
        bool digest_reported = false;
        if (metadata.pe && metadata.pe->certificate_table) {
            const auto &records = metadata.pe->certificate_table->records;
            const auto signed_record = std::find_if(records.begin(), records.end(),
                [](const PeCertificateRecord &record) { return record.type == 0x0002; });
            if (signed_record != records.end()) {
                const auto index = static_cast<std::size_t>(signed_record - records.begin());
                const auto report_signature_verification = [&] {
                    const auto verification = verify_pe_authenticode_signatures(*image, metadata, index);
                    if (verification) {
                        out << "PE Authenticode CMS signature verification (Crypt32; certificate trust not checked):\n";
                        constexpr std::size_t verification_output_limit = 32;
                        const auto verification_rows = (std::min)(verification.value().signers.size(), verification_output_limit);
                        for (std::size_t signer_index = 0; signer_index < verification_rows; ++signer_index) {
                            const auto &status = verification.value().signers[signer_index];
                            out << "  signer=" << signer_index << " signature="
                                << (status.signature_valid ? "verified" : "failed")
                                << (status.signature_valid ? "" : " provider-error=" + std::to_string(status.provider_error))
                                << '\n';
                        }
                        if (verification_rows < verification.value().signers.size())
                            out << "  verification rows omitted=" << verification.value().signers.size() - verification_rows
                                << " (limit " << verification_output_limit << ")\n";
                    } else {
                        out << "PE Authenticode CMS signature verification: unavailable ("
                            << escape_pe_version_text(verification.error().message) << ")\n";
                    }
                };
                const auto match = inspect_pe_authenticode_digest(*image, metadata, index);
                if (match) {
                    auto digest_text = [&](const Sha256Digest &digest) {
                        constexpr char digits[] = "0123456789abcdef";
                        std::string text;
                        text.reserve(match.value().digest_size * 2);
                        for (std::size_t i = 0; i < match.value().digest_size; ++i) {
                            const auto value = std::to_integer<unsigned>(digest[i]);
                            text.push_back(digits[value >> 4]);
                            text.push_back(digits[value & 15]);
                        }
                        return text;
                    };
                    out << "PE Authenticode " << match.value().digest_algorithm << " signed-content digest: "
                        << (match.value().matches ? "matches" : "mismatch")
                        << " certificate-record=" << index
                        << " signed=" << digest_text(match.value().signed_digest)
                        << " image=" << digest_text(match.value().image_digest)
                        << " hashed-bytes=" << match.value().hashed_byte_count
                        << " (CMS signer signature and trust not checked)\n";
                    const auto signer_inventory = inspect_pe_authenticode_signers(*image, metadata, index);
                    if (signer_inventory) {
                        const auto &signers = signer_inventory.value().signers;
                        out << "PE Authenticode CMS signers: " << signers.size() << '\n';
                        constexpr std::size_t signer_output_limit = 32;
                        const auto signer_rows = (std::min)(signers.size(), signer_output_limit);
                        for (std::size_t signer_index = 0; signer_index < signer_rows; ++signer_index) {
                            const auto &signer = signers[signer_index];
                            out << "  signer=" << signer_index << " version=" << signer.version << " id=";
                            if (signer.id_kind == PeAuthenticodeSignerIdKind::issuer_and_serial)
                                out << "issuer-serial(serial=" << signer.serial_number_hex
                                    << ",issuer-der-bytes=" << signer.issuer_der_bytes << ')';
                            else out << "subject-key-id(" << signer.subject_key_identifier_hex << ')';
                            out << " digest-oid=" << signer.digest_algorithm_oid
                                << " signature-oid=" << signer.signature_algorithm_oid
                                << " signature=file:0x" << std::hex << signer.signature_file_offset
                                << "+0x" << signer.signature_size << std::dec
                                << " signed-attrs=" << (signer.signed_attributes_present ? "true" : "false")
                                << " unsigned-attrs=" << (signer.unsigned_attributes_present ? "true" : "false") << '\n';
                        }
                        if (signer_rows < signers.size())
                            out << "  CMS signers omitted=" << signers.size() - signer_rows << " (limit " << signer_output_limit << ")\n";
                        out << "  SignerInfo is structural metadata; cryptographic signature and trust are not checked.\n";
                    } else {
                        out << "PE Authenticode CMS signer inventory: unavailable ("
                            << escape_pe_version_text(signer_inventory.error().message) << ")\n";
                    }
                    digest_reported = true;
                } else {
                    out << "PE Authenticode signed-content digest: unavailable for certificate-record="
                        << index << " (" << escape_pe_version_text(match.error().message) << ")\n";
                }
                report_signature_verification();
            }
        }
        if (!digest_reported) {
            const auto digest = compute_pe_authenticode_sha256(*image, metadata);
            if (digest)
                out << "PE Authenticode SHA-256 image digest: " << digest_hex(digest.value().sha256)
                    << " hashed-bytes=" << digest.value().hashed_byte_count
                    << " (digest only; signature trust not checked)\n"
                    << "PE Authenticode SHA-1 image digest: " << [&] {
                        constexpr char digits[] = "0123456789abcdef";
                        std::string text;
                        text.reserve(digest.value().sha1.size() * 2);
                        for (const auto byte : digest.value().sha1) {
                            const auto value = std::to_integer<unsigned>(byte);
                            text.push_back(digits[value >> 4]);
                            text.push_back(digits[value & 15]);
                        }
                        return text;
                    }()
                    << " hashed-bytes=" << digest.value().hashed_byte_count
                    << " (legacy digest only; signature trust not checked)\n";
            else
                out << "PE Authenticode SHA-256 image digest: unavailable ("
                    << escape_pe_version_text(digest.error().message) << ")\n";
        }
    }
    out << "PE directories:\n";
    const auto directory_count = std::min<std::size_t>(metadata.directories.size(), 16);
    for (std::size_t i = 0; i < directory_count; ++i) {
        const auto &directory = metadata.directories[i];
        out << "  #" << directory.index << " " << (directory.file_offset ? "file:" : "rva:")
            << "0x" << std::hex << directory.location << " size=0x" << directory.size << std::dec << '\n';
    }
    if (metadata.pe) {
        if (metadata.pe->certificate_table) {
            const auto &table = *metadata.pe->certificate_table;
            out << "PE certificates: file=0x" << std::hex << table.file_offset.value
                << " size=0x" << table.size << std::dec << " records=" << table.records.size()
                << (table.complete ? " complete" : " incomplete") << '\n';
            constexpr std::size_t certificate_output_limit = 4096;
            const auto shown = (std::min)(certificate_output_limit, table.records.size());
            for (std::size_t i = 0; i < shown; ++i) {
                const auto &record = table.records[i];
                const auto offset = record.source.spans.empty() ? table.file_offset.value
                                                                 : record.source.spans.front().offset.value;
                out << "  #" << i << " WIN_CERTIFICATE revision=0x" << std::hex << record.revision
                    << " type=0x" << record.type << " file=0x" << offset << std::dec
                    << " length=" << record.length
                    << " alignment-padding="
                    << (record.alignment_padding.empty() ? 0 : record.alignment_padding.front().size)
                    << " padding-nonzero=" << (record.alignment_padding_nonzero ? "true" : "false") << '\n';
            }
            if (shown < table.records.size()) out << "  certificate output limited to 4096 records\n";
            if (!table.complete)
                out << "  certificate inventory diagnostic: "
                    << escape_pe_version_text(table.diagnostic) << '\n';
            out << "  structural inventory only; CMS/signature trust is not verified\n";
        }
        if (metadata.pe->headers) {
            const auto &header = *metadata.pe->headers;
            out << "PE COFF timestamp=0x" << std::hex << header.timestamp
                << " characteristics=0x" << header.characteristics
                << " (file:0x" << header.coff_characteristics_source.value << ")" << std::dec << '\n';
            out << "PE versions: linker=" << header.linker_major << '.' << header.linker_minor
                << " OS=" << header.os_major << '.' << header.os_minor
                << " image=" << header.image_major << '.' << header.image_minor
                << " subsystem=" << header.subsystem_major << '.' << header.subsystem_minor << '\n';
            out << "PE DLL characteristics=0x" << std::hex << header.dll_characteristics
                << " stack-reserve=0x" << header.stack_reserve << " stack-commit=0x" << header.stack_commit
                << " heap-reserve=0x" << header.heap_reserve << " heap-commit=0x" << header.heap_commit
                << " loader-flags=0x" << header.loader_flags << std::dec
                << " directories=" << header.number_of_rva_and_sizes
                << " optional-header-file=0x" << std::hex << header.optional_header_source.value << std::dec << '\n';
        }
        if (metadata.pe->global_pointer_rva) {
            out << "PE global pointer: RVA=0x" << std::hex << *metadata.pe->global_pointer_rva
                << " VA=0x" << (metadata.preferred_base + *metadata.pe->global_pointer_rva)
                << std::dec << '\n';
        }
        if (!metadata.pe->coff_symbols.empty()) {
            constexpr std::size_t coff_symbol_output_limit = 4096;
            out << "PE COFF symbols: " << metadata.pe->coff_symbols.size() << '\n';
            const auto shown=(std::min)(coff_symbol_output_limit,metadata.pe->coff_symbols.size());
            for(std::size_t i=0;i<shown;++i){
                const auto &symbol=metadata.pe->coff_symbols[i];
                out<<"  #"<<symbol.table_index<<" "<<symbol.name<<" section="<<symbol.section_number
                   <<" value=0x"<<std::hex<<symbol.value<<std::dec<<" class="<<unsigned(symbol.storage_class)
                   <<" aux="<<unsigned(symbol.auxiliary_count)<<" file=0x"<<std::hex<<symbol.source_file_offset.value<<std::dec;
                if(symbol.address)out<<" VA=0x"<<std::hex<<symbol.address->offset<<std::dec;
                if(symbol.function_size)out<<" function-size=0x"<<std::hex<<*symbol.function_size
                    <<" aux-file=0x"<<symbol.function_aux_file_offset.value<<std::dec;
                out<<'\n';
                if (symbol.section_definition) {
                    const auto &section = *symbol.section_definition;
                    static constexpr const char *selection_names[] = {
                        "none", "no-duplicates", "any", "same-size", "exact-match", "associative", "largest", "newest"};
                    out << "    section-aux length=" << section.length << " relocations=" << section.relocation_count
                        << " line-numbers=" << section.line_number_count << " checksum=0x" << std::hex
                        << section.checksum << std::dec << " associated-section=" << section.associated_section
                        << " selection=" << unsigned(section.selection);
                    if (section.selection < std::size(selection_names))
                        out << '(' << selection_names[section.selection] << ')';
                    out << " file=0x" << std::hex << section.source_file_offset.value << std::dec << '\n';
                }
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
        std::size_t emitted_string_tables = 0, emitted_resource_strings = 0;
        for (const auto &resource : metadata.pe->resources) {
            if (!resource.string_table) continue;
            if (emitted_string_tables == 256) {
                out << "PE RT_STRING tables: output limited to 256 resources\n";
                break;
            }
            const auto &table = *resource.string_table;
            out << "PE RT_STRING table=" << (resource.name.id ? std::to_string(*resource.name.id) : "?")
                << " language=" << (resource.language.id ? std::to_string(*resource.language.id) : "?")
                << " entries=" << table.entries.size()
                << (table.complete ? " complete" : " incomplete");
            if (!table.source.spans.empty())
                out << " file:0x" << std::hex << table.source.spans.front().offset.value << std::dec;
            out << '\n';
            for (const auto &entry : table.entries) {
                if (emitted_resource_strings == 4096) {
                    out << "  PE RT_STRING entries: output limited to 4096 strings\n";
                    break;
                }
                out << "  PE string id=" << entry.id << " value=\"" << escape_pe_version_text(entry.value) << '"';
                if (!entry.source.spans.empty())
                    out << " file:0x" << std::hex << entry.source.spans.front().offset.value << std::dec;
                out << '\n';
                ++emitted_resource_strings;
            }
            ++emitted_string_tables;
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
        std::size_t emitted_icon_groups = 0, emitted_icon_entries = 0;
        for (std::size_t resource_index = 0; resource_index < metadata.pe->resources.size(); ++resource_index) {
            const auto &resource = metadata.pe->resources[resource_index];
            if (!resource.group_icon) continue;
            if (emitted_icon_groups == 256) {
                out << "PE group icon resources: output limited to 256 rows\n";
                break;
            }
            const auto &group = *resource.group_icon;
            out << "PE group icon resource name=";
            if (resource.name.name) out << '"' << escape_pe_version_text(*resource.name.name) << '"';
            else if (resource.name.id) out << *resource.name.id;
            else out << "?";
            out << " language=";
            if (resource.language.id) out << *resource.language.id;
            else if (resource.language.name) out << '"' << escape_pe_version_text(*resource.language.name) << '"';
            else out << "?";
            out << (group.complete ? " complete" : " incomplete");
            if (!group.source.spans.empty())
                out << " file:0x" << std::hex << group.source.spans.front().offset.value << std::dec;
            out << '\n';
            for (const auto &entry : group.entries) {
                if (emitted_icon_entries == 4096) {
                    out << "  PE group icon entries: output limited to 4096 rows\n";
                    break;
                }
                const auto width = entry.width ? static_cast<unsigned>(entry.width) : 256u;
                const auto height = entry.height ? static_cast<unsigned>(entry.height) : 256u;
                out << "  icon id=" << entry.icon_id << " size=" << width << 'x' << height
                    << " planes=" << entry.planes << " bits=" << entry.bit_count
                    << " bytes=" << entry.bytes_in_resource;
                if (entry.icon_resource_index) out << " resource-index=" << *entry.icon_resource_index;
                else out << " resource-index=unresolved";
                if (!entry.source.spans.empty())
                    out << " file:0x" << std::hex << entry.source.spans.front().offset.value << std::dec;
                out << '\n';
                ++emitted_icon_entries;
            }
            ++emitted_icon_groups;
        }
        std::size_t emitted_cursor_groups = 0, emitted_cursor_entries = 0;
        for (const auto &resource : metadata.pe->resources) {
            if (!resource.group_cursor) continue;
            if (emitted_cursor_groups == 256) {
                out << "PE group cursor resources: output limited to 256 rows\n";
                break;
            }
            const auto &group = *resource.group_cursor;
            out << "PE group cursor resource name=";
            if (resource.name.name) out << '"' << escape_pe_version_text(*resource.name.name) << '"';
            else if (resource.name.id) out << *resource.name.id;
            else out << "?";
            out << " language=";
            if (resource.language.id) out << *resource.language.id;
            else if (resource.language.name) out << '"' << escape_pe_version_text(*resource.language.name) << '"';
            else out << "?";
            out << (group.complete ? " complete" : " incomplete");
            if (!group.source.spans.empty())
                out << " file:0x" << std::hex << group.source.spans.front().offset.value << std::dec;
            out << '\n';
            for (const auto &entry : group.entries) {
                if (emitted_cursor_entries == 4096) {
                    out << "  PE group cursor entries: output limited to 4096 rows\n";
                    break;
                }
                out << "  cursor id=" << entry.cursor_id << " size=" << entry.width << 'x' << entry.height
                    << " planes=" << entry.planes << " bits=" << entry.bit_count
                    << " bytes=" << entry.bytes_in_resource;
                if (entry.cursor_resource_index) out << " resource-index=" << *entry.cursor_resource_index;
                else out << " resource-index=unresolved";
                if (entry.resource_size_matches)
                    out << " size-match=" << (*entry.resource_size_matches ? "true" : "false");
                if (!entry.source.spans.empty())
                    out << " file:0x" << std::hex << entry.source.spans.front().offset.value << std::dec;
                out << '\n';
                ++emitted_cursor_entries;
            }
            ++emitted_cursor_groups;
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
        const auto callback_count = (std::min)(tls.callbacks.size(), tls_callback_output_limit);
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
            << " guard-flags=0x" << std::hex << config.guard_flags << std::dec;
        const auto source_offset = [](const std::optional<PeRecordSource> &source) -> std::optional<std::uint64_t> {
            if (!source || source->spans.empty()) return {};
            return source->spans.front().offset.value;
        };
        if (const auto offset = source_offset(config.declared_size_source))
            out << " size-file=0x" << std::hex << *offset;
        if (const auto offset = source_offset(config.version_source))
            out << " version-file=0x" << std::hex << *offset;
        if (const auto offset = source_offset(config.guard_flags_source))
            out << " guard-flags-file=0x" << std::hex << *offset;
        out << std::dec << '\n';
        if (config.security_cookie_rva) {
            out << "  Security cookie RVA=0x" << std::hex << *config.security_cookie_rva;
            if (const auto offset = source_offset(config.security_cookie_source))
                out << " file=0x" << *offset;
            out << std::dec << '\n';
        }
        if (config.guard_function_table_rva || config.guard_function_table_count) {
            out << "  Guard CF function table";
            if (config.guard_function_table_rva)
                out << " RVA=0x" << std::hex << *config.guard_function_table_rva;
            if (config.guard_function_table_count)
                out << std::dec << " count=" << *config.guard_function_table_count;
            if (const auto offset = source_offset(config.guard_function_table_pointer_source))
                out << " table-file=0x" << std::hex << *offset;
            if (const auto offset = source_offset(config.guard_function_table_count_source))
                out << " count-file=0x" << *offset;
            out << std::dec << '\n';
        }
        if (config.code_integrity) {
            const auto &ci = *config.code_integrity;
            out << "  Code integrity flags=0x" << std::hex << ci.flags
                << " catalog=0x" << ci.catalog << " catalog-offset=0x" << ci.catalog_offset
                << " reserved=0x" << ci.reserved;
            if (!ci.source.spans.empty())
                out << " file=0x" << ci.source.spans.front().offset.value;
            out << std::dec << '\n';
        }
        const auto pointer = [&](const char *name, std::optional<std::uint64_t> rva) {
            if (rva) out << "  " << name << " RVA=0x" << std::hex << *rva << std::dec << '\n';
        };
        pointer("Guard CF check", config.guard_check_rva);
        pointer("Guard CF dispatch", config.guard_dispatch_rva);
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
            out << "  redirections=" << chpe.redirections.size();
            if (chpe.redirection_metadata_count)
                out << " table-RVA=0x" << std::hex << chpe.redirection_metadata_rva << std::dec;
            out << '\n';
            const auto redirection_count = std::min<std::size_t>(chpe.redirections.size(), 4096);
            for (std::size_t i = 0; i < redirection_count; ++i) {
                const auto &row = chpe.redirections[i];
                out << "    redirect source-RVA=0x" << std::hex << row.source_rva
                    << " destination-RVA=0x" << row.destination_rva << std::dec;
                if (!row.source.spans.empty())
                    out << " file=0x" << std::hex << row.source.spans.front().offset.value << std::dec;
                out << '\n';
            }
            if (redirection_count != chpe.redirections.size())
                out << "  ... CHPE redirection output limited to 4096 rows\n";
            out << "  validated per-range decode contexts are retained in the image execution profile\n";
        }
    }
    if (metadata.pe && !metadata.pe->bound_imports.empty()) {
        out << "PE bound imports:\n";
        std::size_t emitted = 0;
        const auto emit_name_source = [&](const std::vector<PeSourceSpan> &spans) {
            if (spans.empty()) return;
            out << " name-source=";
            for (std::size_t span = 0; span < spans.size(); ++span) {
                if (span) out << ',';
                out << "0x" << std::hex << spans[span].offset.value << "+0x" << spans[span].size;
            }
            out << std::dec;
        };
        for (const auto &item : metadata.pe->bound_imports) {
            if (emitted >= 4096) break;
            out << "  " << item.library << " timestamp=0x" << std::hex << item.timestamp << std::dec;
            if (!item.descriptor.spans.empty()) out << " file:0x" << std::hex << item.descriptor.spans.front().offset.value << std::dec;
            emit_name_source(item.library_name);
            out << '\n';
            ++emitted;
            for (const auto &forwarder : item.forwarders) {
                if (emitted >= 4096) break;
                out << "    -> " << forwarder.library << " timestamp=0x" << std::hex << forwarder.timestamp << std::dec;
                if (!forwarder.descriptor.spans.empty()) out << " file:0x" << std::hex << forwarder.descriptor.spans.front().offset.value << std::dec;
                emit_name_source(forwarder.library_name);
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
    if (metadata.pe && !metadata.pe->pdb_checksums.empty()) {
        out << "PE PDB checksum records: " << metadata.pe->pdb_checksums.size();
        if (metadata.pe->pdb_checksum_verified)
            out << " local-pdb=" << (*metadata.pe->pdb_checksum_verified ? "verified" : "mismatch");
        out << '\n';
        const auto count = std::min<std::size_t>(metadata.pe->pdb_checksums.size(), 256);
        for (std::size_t i = 0; i < count; ++i) {
            const auto &checksum = metadata.pe->pdb_checksums[i];
            out << "  algorithm=" << escape_pe_version_text(checksum.algorithm) << " digest=";
            for (const auto byte : checksum.digest)
                out << std::hex << std::setw(2) << std::setfill('0')
                    << std::to_integer<unsigned>(byte);
            out << std::dec << std::setfill(' ');
            if (!checksum.source.spans.empty())
                out << " file=0x" << std::hex << checksum.source.spans.front().offset.value << std::dec;
            out << '\n';
        }
        if (count != metadata.pe->pdb_checksums.size())
            out << "  ... PDB checksum output limited to 256 rows; omitted="
                << metadata.pe->pdb_checksums.size() - count << '\n';
    }
    if (metadata.pe && !metadata.pe->debug_directories.empty()) {
        const auto &directories = metadata.pe->debug_directories;
        out << "PE debug directories: " << directories.size() << '\n';
        constexpr std::size_t debug_directory_limit = 256, repro_hash_preview = 64;
        const auto count = (std::min)(directories.size(), debug_directory_limit);
        for (std::size_t index = 0; index < count; ++index) {
            const auto &entry = directories[index];
            out << "  [" << index << "] type=" << entry.type << " size=" << entry.data_size;
            if (!entry.entry.spans.empty())
                out << " entry-file=0x" << std::hex << entry.entry.spans.front().offset.value << std::dec;
            if (!entry.raw_data.empty())
                out << " data-file=0x" << std::hex << entry.raw_data.front().offset.value << std::dec;
            if (entry.reproducible_build) {
                out << " reproducible-build=yes";
                if (!entry.reproducible_hash.empty()) {
                    out << " hash=";
                    const auto bytes = (std::min)(entry.reproducible_hash.size(), repro_hash_preview);
                    for (std::size_t i = 0; i < bytes; ++i)
                        out << std::hex << std::setw(2) << std::setfill('0')
                            << std::to_integer<unsigned>(entry.reproducible_hash[i]);
                    out << std::dec << std::setfill(' ');
                    if (bytes < entry.reproducible_hash.size())
                        out << "...(" << entry.reproducible_hash.size() << " bytes)";
                } else out << " hash=absent";
            }
            if (entry.extended_dll_characteristics) {
                const auto flags = *entry.extended_dll_characteristics;
                out << " extended-dll-characteristics=0x" << std::hex << flags << std::dec
                    << " cet-compat=" << ((flags & 0x0001u) ? "yes" : "no")
                    << " forward-cfi-compat=" << ((flags & 0x0040u) ? "yes" : "no")
                    << " unknown-bits=0x" << std::hex << (flags & ~0x0041u) << std::dec;
            }
            out << '\n';
        }
        if (count != directories.size())
            out << "  ... debug directory output limited to " << debug_directory_limit << " rows; omitted="
                << directories.size() - count << '\n';
    }
    if (metadata.pe && !metadata.pe->codeview.empty()) {
        out << "PE CodeView identities: " << metadata.pe->codeview.size() << '\n';
        const auto count = std::min<std::size_t>(metadata.pe->codeview.size(), 256);
        for (std::size_t i = 0; i < count; ++i) {
            const auto &identity = metadata.pe->codeview[i];
            out << "  " << (identity.rsds ? "RSDS" : "NB10") << " path=\""
                << escape_pe_version_text(identity.path) << "\" age=" << identity.age;
            if (identity.rsds) {
                out << " guid=";
                for (const auto byte : identity.guid)
                    out << std::hex << std::setw(2) << std::setfill('0')
                        << std::to_integer<unsigned>(byte);
                out << std::dec << std::setfill(' ');
            }
            else out << " signature=0x" << std::hex << identity.nb10_signature
                     << " timestamp=0x" << identity.nb10_timestamp << std::dec;
            if (!identity.record.empty()) out << " file=0x" << std::hex << identity.record.front().offset.value << std::dec;
            out << '\n';
        }
        if (count < metadata.pe->codeview.size())
            out << "  CodeView output limited to 256 rows; omitted=" << metadata.pe->codeview.size() - count << '\n';
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

