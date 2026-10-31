#include "hexlab/loaders/recipe.hpp"
#include "hexlab/loaders/elf.hpp"
#include "hexlab/image/file_storage.hpp"
#include "hexlab/image/read_set.hpp"
#include "hexlab/loaders/pdb_lines.hpp"
#include "hexlab/loaders/firmware.hpp"
#include "hexlab/loaders/wasm.hpp"
#include "hexlab/loaders/dex.hpp"
#include "hexlab/loaders/jvm.hpp"
#include "hexlab/loaders/minidump.hpp"
#include "macho_internal.hpp"
#include <stdexcept>
#include <algorithm>
#include <array>
#include <cctype>
#include <mutex>
#include <string_view>
#include <system_error>
namespace hexlab {
namespace {
bool has_local_pe_pdb_candidate(const std::filesystem::path &image_path, std::stop_token stop) {
    constexpr std::size_t max_directory_entries = 4096;
    auto fallback = image_path.filename();
    fallback.replace_extension(".pdb");
    std::error_code error;
    auto status = std::filesystem::symlink_status(image_path.parent_path() / fallback, error);
    if (!error && std::filesystem::is_regular_file(status)) return true;
    error.clear();
    std::filesystem::directory_iterator entry(image_path.parent_path(), error), end;
    if (error) return true; // Do the authoritative metadata pass if discovery was inconclusive.
    std::size_t visited = 0;
    while (entry != end && visited++ < max_directory_entries) {
        if ((visited & 63u) == 0 && stop.stop_requested()) return false;
        auto extension = entry->path().extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(),
                       [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if (extension == ".pdb") {
            error.clear();
            status = std::filesystem::symlink_status(entry->path(), error);
            if (!error && std::filesystem::is_regular_file(status)) return true;
        }
        entry.increment(error);
        if (error) return true;
    }
    // If the enumeration budget was reached, a sidecar may be beyond the
    // bounded prefix, so retain the exact CodeView check rather than assume none.
    return entry != end;
}
Result<LoadRecipe> attach_adjacent_pe_pdb(const ByteStorage &storage, LoadRecipe recipe,
                                          std::stop_token stop) {
    if (recipe.format != Format::pe || recipe.pdb_path)
        return recipe;
    const auto *file = dynamic_cast<const FileStorage *>(&storage);
    if (!file)
        return recipe;
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Image loading canceled"};
    if (!has_local_pe_pdb_candidate(file->backing_path(), stop)) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Image loading canceled"};
        return recipe;
    }
    auto parsed = load_pe(file->shared_from_this(), stop);
    if (!parsed) {
        if (parsed.error().code == ErrorCode::canceled) return parsed.error();
        return recipe;
    }
    std::vector<std::filesystem::path> names;
    if (parsed.value().metadata.pe) {
        for (const auto &identity : parsed.value().metadata.pe->codeview) {
            if (!identity.rsds || identity.path.empty()) continue;
            const auto separator = identity.path.find_last_of("/\\");
            const auto basename = std::string_view(identity.path).substr(
                separator == std::string::npos ? 0 : separator + 1);
            if (basename.empty() || basename == "." || basename == "..") continue;
            std::filesystem::path name;
            try {
                const auto *utf8 = reinterpret_cast<const char8_t *>(basename.data());
                name = std::u8string(utf8, utf8 + basename.size());
            } catch (const std::filesystem::filesystem_error &) {
                continue;
            }
            if (!name.empty() && name != "." && name != ".." &&
                std::find(names.begin(), names.end(), name) == names.end())
                names.push_back(name);
        }
    }
    auto fallback = file->backing_path().filename();
    fallback.replace_extension(".pdb");
    if (!fallback.empty() && std::find(names.begin(), names.end(), fallback) == names.end())
        names.push_back(std::move(fallback));
    for (const auto &name : names) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Image loading canceled"};
        const auto candidate = file->backing_path().parent_path() / name;
        std::error_code error;
        const auto status = std::filesystem::symlink_status(candidate, error);
        // Treat CodeView paths as untrusted hints: only inspect a basename in
        // the input directory, and never follow a symlink automatically.
        if (!error && std::filesystem::is_regular_file(status)) {
            recipe.pdb_path = candidate;
            break;
        }
    }
    return recipe;
}
Sha256Digest combine_external_fingerprints(const std::optional<Sha256Digest> &first,
                                           const Sha256Digest &second) {
    Sha256 combined;
    constexpr std::array<std::byte, 8> domain = {
        std::byte{'H'}, std::byte{'L'}, std::byte{'E'}, std::byte{'X'},
        std::byte{'E'}, std::byte{'X'}, std::byte{'T'}, std::byte{1}};
    (void)combined.update(domain);
    if (first) {
        constexpr std::array<std::byte, 1> first_tag{std::byte{1}};
        (void)combined.update(first_tag);
        (void)combined.update(*first);
    }
    constexpr std::array<std::byte, 1> second_tag{std::byte{2}};
    (void)combined.update(second_tag);
    (void)combined.update(second);
    return combined.digest();
}
bool valid_plugin_identity(const PluginImageIdentity &identity) {
    const auto text = [](const std::string &s) {
        return !s.empty() && s.size() < 1024 && s.find('\0') == s.npos;
    };
    return identity.api_version == 1 && text(identity.plugin_id) && text(identity.plugin_version) &&
           text(identity.extension_id) && text(identity.format_id);
}
struct PluginProvider {
    PluginImageIdentity identity;
    PluginImageLoader load;
    PluginImageProbe probe;
};
std::mutex provider_mutex;
std::vector<std::weak_ptr<PluginProvider>> providers;
thread_local bool in_provider_dispatch = false;
struct ProviderDispatchScope {
    ProviderDispatchScope() { in_provider_dispatch = true; }
    ~ProviderDispatchScope() { in_provider_dispatch = false; }
};
Result<std::optional<PluginImageIdentity>> probe_plugin_image(const ByteStorage &storage, std::stop_token stop) {
    if (in_provider_dispatch)
        return Error{ErrorCode::busy, "Recursive plugin image probing is unsupported"};
    ProviderDispatchScope dispatch;
    try {
        std::vector<std::shared_ptr<PluginProvider>> active;
        {
            std::lock_guard lock(provider_mutex);
            for (const auto &weak : providers)
                if (auto provider = weak.lock(); provider && provider->probe)
                    active.push_back(std::move(provider));
        }
        if (active.empty() || !storage.size()) return std::optional<PluginImageIdentity>{};
        auto prefix = storage.read_at({0}, static_cast<std::size_t>(std::min<std::uint64_t>(storage.size(), 4096)));
        if (!prefix) return prefix.error();
        if (prefix.value().bytes.size() != std::min<std::uint64_t>(storage.size(), 4096))
            return Error{ErrorCode::io, "Short read while probing plugin image providers"};
        std::optional<PluginImageIdentity> best;
        std::uint32_t confidence = 0;
        std::optional<Error> failure;
        for (const auto &provider : active) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Plugin image probing canceled"};
            auto result = provider->probe(prefix.value().bytes, storage.size(), stop);
            if (!result) {
                if (result.error().code == ErrorCode::canceled) return result.error();
                if (!failure) failure = result.error();
                continue;
            }
            if (!result.value()) continue;
            if (*result.value() > 1000) {
                if (!failure) failure = Error{ErrorCode::io, "Invalid plugin image probe confidence"};
                continue;
            }
            if (!best || *result.value() > confidence) {
                best = provider->identity;
                confidence = *result.value();
            }
        }
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Plugin image probing canceled"};
        if (best) return best;
        if (failure) return *failure;
        return std::optional<PluginImageIdentity>{};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate plugin probe state"};
    } catch (...) { return Error{ErrorCode::io, "Plugin image probe raised an exception"}; }
}
Result<LoadedImage> load_plugin(std::shared_ptr<const ByteStorage> storage,
                               const PluginImageIdentity &identity, std::stop_token stop) {
    if (in_provider_dispatch)
        return Error{ErrorCode::busy, "Recursive plugin image loading is unsupported"};
    ProviderDispatchScope dispatch;
    std::shared_ptr<PluginProvider> selected;
    {
        std::lock_guard lock(provider_mutex);
        for (const auto &weak : providers)
            if (auto provider = weak.lock(); provider && provider->identity == identity) {
                selected = std::move(provider);
                break;
            }
    }
    if (!selected)
        return Error{ErrorCode::unsupported, "Exact plugin image provider is not loaded"};
    try {
        auto tracking = TrackingStorage::create(std::move(storage));
        if (!tracking)
            return tracking.error();
        auto loaded = selected->load(tracking.value(), stop);
        if (!loaded)
            return loaded.error();
        const bool image_uses_tracked_source = loaded.value().image &&
            loaded.value().image->storage().get() == tracking.value().get();
        // Replace plugin-reported ranges with the authoritative ByteStorage
        // observations. Certification remains the provider's responsibility
        // because it may depend on sidecars or other external state.
        loaded.value().metadata_reads = tracking.value()->reads();
        loaded.value().metadata_reads_complete = loaded.value().metadata_reads_complete &&
            image_uses_tracked_source;
        return loaded;
    }
    catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate plugin image"};
    } catch (...) { return Error{ErrorCode::io, "Plugin image provider raised an exception"}; }
}
bool valid(const LoadRecipe &recipe) {
    const bool known_pe_target = !recipe.pe_runtime_architecture ||
        *recipe.pe_runtime_architecture == PeRuntimeArchitecture::arm64 ||
        *recipe.pe_runtime_architecture == PeRuntimeArchitecture::x64_compatible;
    if (!known_pe_target)
        return false;
    if (recipe.format == Format::plugin)
        return recipe.plugin && valid_plugin_identity(*recipe.plugin) && !recipe.raw && !recipe.macho &&
               !recipe.pdb_path && !recipe.pe_runtime_architecture && !recipe.dwarf_supplementary_package_path;
    if (recipe.plugin) return false;
    if (recipe.dwarf_supplementary_package_path &&
        (recipe.format != Format::elf || recipe.dwarf_supplementary_package_path->empty() ||
         recipe.dwarf_supplementary_package_path->native().find(std::filesystem::path::value_type{}) !=
             recipe.dwarf_supplementary_package_path->native().npos))
        return false;
    if (recipe.dwarf_supplementary_package_path &&
        recipe.dwarf_supplementary_package_path->u8string().size() > 32768)
        return false;
    if (recipe.pe_runtime_architecture && recipe.format != Format::pe)
        return false;
    if (recipe.pdb_path && recipe.format != Format::pe)
        return false;
    if (recipe.minidump_pdb_paths.size() > 128 ||
        (recipe.format != Format::minidump && (!recipe.minidump_pdb_paths.empty() || recipe.minidump_pdb_search_truncated)))
        return false;
    std::size_t minidump_pdb_path_bytes = 0;
    for (const auto &path : recipe.minidump_pdb_paths) {
        if (path.empty() || path.native().find(std::filesystem::path::value_type{}) != path.native().npos)
            return false;
        const auto size = path.u8string().size();
        if (size > 32768 || minidump_pdb_path_bytes > 1024 * 1024 - size)
            return false;
        minidump_pdb_path_bytes += size;
    }
    if (recipe.pdb_path && (recipe.pdb_path->empty() ||
        recipe.pdb_path->native().find(std::filesystem::path::value_type{}) != recipe.pdb_path->native().npos))
        return false;
    if (recipe.format == Format::ar || recipe.format == Format::intel_hex || recipe.format == Format::s_record)
        return !recipe.raw && !recipe.macho;
    if (recipe.format == Format::wasm)
        return !recipe.raw && !recipe.macho && !recipe.pdb_path;
    if (recipe.format == Format::dex)
        return !recipe.raw && !recipe.macho && !recipe.pdb_path;
    if (recipe.format == Format::jvm)
        return !recipe.raw && !recipe.macho && !recipe.pdb_path;
    if (recipe.format == Format::minidump)
        return !recipe.raw && !recipe.macho && !recipe.pdb_path && !recipe.pe_runtime_architecture;
    if (recipe.format == Format::macho)
        return !recipe.raw;
    if (recipe.macho)
        return false;
    if (recipe.format == Format::pe || recipe.format == Format::elf)
        return !recipe.raw;
    if (recipe.format != Format::raw || !recipe.raw)
        return false;
    const auto &raw = *recipe.raw;
    return bool(validate_raw_coordinates(raw));
}
void integer(std::vector<std::byte> &out, uint64_t value, size_t width) {
    for (size_t i = width; i > 0; --i)
        out.push_back(std::byte(value >> ((i - 1) * 8)));
}
std::optional<std::filesystem::path> discover_local_supplementary_dwp(
    const std::filesystem::path &primary_path, const symbols::DwarfSupplementaryIdentity &identity) noexcept {
    try {
        const std::filesystem::path hint = std::filesystem::u8path(identity.filename);
        if (identity.filename.empty() || hint.is_absolute() || hint.has_root_path() ||
            hint != hint.filename() || hint == "." || hint == "..")
            return {};
        std::error_code ec;
        const auto source = std::filesystem::canonical(primary_path, ec);
        if (ec) return {};
        const auto candidate = std::filesystem::canonical(source.parent_path() / hint, ec);
        if (ec || candidate.parent_path() != source.parent_path() || candidate == source ||
            !std::filesystem::is_regular_file(candidate, ec) || ec)
            return {};
        const auto size = std::filesystem::file_size(candidate, ec);
        if (ec || size > UINT64_C(64) * 1024 * 1024) return {};
        return candidate;
    } catch (...) {
        // Malformed path encodings are treated as unavailable hints.
        return {};
    }
}
std::optional<std::filesystem::path> discover_local_split_dwp(
    const std::filesystem::path &primary_path) noexcept {
    try {
        std::error_code ec;
        const auto source = std::filesystem::canonical(primary_path, ec);
        if (ec) return {};
        auto candidate_name = source.filename().native();
        candidate_name += std::filesystem::path(".dwp").native();
        const auto unresolved = source.parent_path() / std::filesystem::path(candidate_name);
        const auto link_status = std::filesystem::symlink_status(unresolved, ec);
        if (ec || std::filesystem::is_symlink(link_status) || !std::filesystem::is_regular_file(link_status)) return {};
        const auto candidate = std::filesystem::canonical(unresolved, ec);
        if (ec || candidate.parent_path() != source.parent_path() || candidate == source) return {};
        const auto size = std::filesystem::file_size(candidate, ec);
        if (ec || size > UINT64_C(64) * 1024 * 1024) return {};
        return candidate;
    } catch (...) {
        return {};
    }
}
} // namespace
Result<std::shared_ptr<void>> register_plugin_image_provider(const PluginImageIdentity &identity,
                                                            PluginImageLoader load, PluginImageProbe probe) {
    if (!valid_plugin_identity(identity) || !load)
        return Error{ErrorCode::invalid_argument, "Invalid plugin image provider"};
    try {
        std::lock_guard lock(provider_mutex);
        std::erase_if(providers, [](const auto &value) { return value.expired(); });
        for (const auto &weak : providers)
            if (auto provider = weak.lock(); provider && provider->identity == identity)
                return Error{ErrorCode::conflict, "Exact plugin image provider is already registered"};
        if (providers.size() >= 4096)
            return Error{ErrorCode::resource_limit, "Plugin image provider registry is full"};
        auto provider = std::make_shared<PluginProvider>(PluginProvider{identity, std::move(load), std::move(probe)});
        providers.push_back(provider);
        return std::static_pointer_cast<void>(std::move(provider));
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot register plugin image provider"};
    }
}
Result<std::vector<std::byte>> encode_recipe(const LoadRecipe &recipe) {
    if (!valid(recipe))
        return Error{ErrorCode::invalid_argument, "Invalid durable load recipe"};
    try {
        if (recipe.plugin) {
            std::vector<std::byte> out{std::byte{6}, std::byte{0}, std::byte{10}};
            integer(out, recipe.plugin->api_version, 4);
            for (const auto *text : {&recipe.plugin->plugin_id, &recipe.plugin->plugin_version,
                                    &recipe.plugin->extension_id, &recipe.plugin->format_id}) {
                integer(out, text->size(), 2);
                for (unsigned char ch : *text) out.push_back(std::byte(ch));
            }
            return out;
        }
        if (recipe.format == Format::intel_hex || recipe.format == Format::s_record)
            return std::vector<std::byte>{std::byte{5}, std::byte{0},
                std::byte(recipe.format == Format::intel_hex ? 8 : 9)};
        if (recipe.format == Format::wasm)
            return std::vector<std::byte>{std::byte{1}, std::byte{0}, std::byte{11}};
        if (recipe.format == Format::dex)
            return std::vector<std::byte>{std::byte{1}, std::byte{0}, std::byte{12}};
        if (recipe.format == Format::jvm)
            return std::vector<std::byte>{std::byte{1}, std::byte{0}, std::byte{13}};
        if (recipe.format == Format::minidump) {
            if (recipe.minidump_pdb_paths.empty() && !recipe.minidump_pdb_search_truncated)
                return std::vector<std::byte>{std::byte{1}, std::byte{0}, std::byte{16}};
            std::vector<std::byte> out{std::byte{2}, std::byte{0}, std::byte{18}};
            integer(out, recipe.minidump_pdb_paths.size(), 2);
            out.push_back(std::byte(recipe.minidump_pdb_search_truncated ? 1 : 0));
            for (const auto &path : recipe.minidump_pdb_paths) {
                const auto encoded = path.u8string();
                integer(out, encoded.size(), 4);
                for (auto c : encoded) out.push_back(std::byte(static_cast<unsigned char>(c)));
            }
            return out;
        }
        if (recipe.format == Format::pe && recipe.pe_runtime_architecture) {
            const auto target = static_cast<std::byte>(*recipe.pe_runtime_architecture);
            if (!recipe.pdb_path)
                return std::vector<std::byte>{std::byte{1}, std::byte{0}, std::byte{14}, target};
            const auto encoded = recipe.pdb_path->u8string();
            if (encoded.size() > 32768)
                return Error{ErrorCode::resource_limit, "PDB path exceeds recipe limit"};
            std::vector<std::byte> out{std::byte{2}, std::byte{0}, std::byte{15}, target};
            integer(out, encoded.size(), 4);
            for (auto c : encoded) out.push_back(std::byte(static_cast<unsigned char>(c)));
            return out;
        }
        if (recipe.format == Format::macho) {
            const auto selected = recipe.macho ? recipe.macho->slice_index : std::nullopt;
            std::vector<std::byte> out{std::byte{1}, std::byte{0}, std::byte{5}, std::byte(selected ? 1 : 0)};
            if (selected)
                integer(out, *selected, 4);
            return out;
        }
        if (recipe.format == Format::elf && recipe.dwarf_supplementary_package_path) {
            const auto encoded = recipe.dwarf_supplementary_package_path->u8string();
            if (encoded.empty() || encoded.size() > 32768)
                return Error{ErrorCode::resource_limit, "DWARF supplementary package path exceeds recipe limit"};
            std::vector<std::byte> out{std::byte{2}, std::byte{0}, std::byte{17}};
            integer(out, encoded.size(), 4);
            for (auto c : encoded) out.push_back(std::byte(static_cast<unsigned char>(c)));
            return out;
        }
        if (recipe.format == Format::pe && recipe.pdb_path) {
            const auto encoded = recipe.pdb_path->u8string();
            if (encoded.size() > 32768)
                return Error{ErrorCode::resource_limit, "PDB path exceeds recipe limit"};
            std::vector<std::byte> out{std::byte{2}, std::byte{0}, std::byte{7}};
            integer(out, encoded.size(), 4);
            for (auto c : encoded) out.push_back(std::byte(static_cast<unsigned char>(c)));
            return out;
        }
        if (recipe.raw && recipe.raw->arm_profile) {
            auto text = format_arm_profile(*recipe.raw->arm_profile);
            if (!text)
                return text.error();
            std::vector<std::byte> out{std::byte{3}, std::byte{0}, std::byte{6}};
            integer(out, text.value().size(), 4);
            const auto bytes = std::as_bytes(std::span(text.value()));
            out.insert(out.end(), bytes.begin(), bytes.end());
            return out;
        }
        if (recipe.raw && recipe.raw->x86_profile) {
            auto text = format_x86_profile(*recipe.raw->x86_profile);
            if (!text)
                return text.error();
            std::vector<std::byte> out{std::byte{2}, std::byte{0}, std::byte{3}};
            integer(out, text.value().size(), 4);
            const auto bytes = std::as_bytes(std::span(text.value()));
            out.insert(out.end(), bytes.begin(), bytes.end());
            return out;
        }
        const bool explicit_order = recipe.raw && recipe.raw->order == ByteOrder::big;
        std::vector<std::byte> out{std::byte(explicit_order ? 4 : 1), std::byte{0},
                                   std::byte(recipe.format == Format::raw   ? 1
                                             : recipe.format == Format::elf ? 4
                                             : recipe.format == Format::ar  ? 6
                                                                            : 2)};
        if (recipe.raw) {
            const auto &raw = *recipe.raw;
            out.push_back(std::byte(raw.architecture));
            out.push_back(std::byte(raw.mode));
            out.push_back(std::byte((raw.readable ? 1 : 0) | (raw.writable ? 2 : 0) | (raw.executable ? 4 : 0)));
            integer(out, raw.base.space.value, 4);
            integer(out, raw.base.offset, 8);
            out.push_back(std::byte(raw.entry ? 1 : 0));
            if (raw.entry) {
                integer(out, raw.entry->space.value, 4);
                integer(out, raw.entry->offset, 8);
            }
            if (explicit_order)
                out.push_back(std::byte{1});
        }
        return out;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate load recipe"};
    }
}
Result<LoadRecipe> decode_recipe(std::span<const std::byte> bytes) {
    if (bytes.size() >= 7 && bytes[0] == std::byte{2} && bytes[1] == std::byte{0} &&
        bytes[2] == std::byte{17}) {
        std::uint64_t size = 0;
        for (std::size_t i = 3; i < 7; ++i) size = (size << 8) | std::to_integer<unsigned>(bytes[i]);
        if (size == 0 || size > 32768 || size != bytes.size() - 7)
            return Error{ErrorCode::malformed, "Invalid ELF/DWARF supplementary package recipe path"};
        std::u8string path;
        path.reserve(static_cast<std::size_t>(size));
        for (std::size_t i = 7; i < bytes.size(); ++i)
            path.push_back(char8_t(std::to_integer<unsigned char>(bytes[i])));
        auto decoded = std::filesystem::path(path);
        if (decoded.empty() || decoded.native().find(std::filesystem::path::value_type{}) != decoded.native().npos)
            return Error{ErrorCode::malformed, "Invalid ELF/DWARF supplementary package recipe path"};
        LoadRecipe recipe{Format::elf, {}};
        recipe.dwarf_supplementary_package_path = std::move(decoded);
        return recipe;
    }
    if (bytes.size() >= 3 && bytes[0] == std::byte{6} && bytes[1] == std::byte{0} && bytes[2] == std::byte{10}) {
        if (bytes.size() < 7 || bytes.size() > 4107)
            return Error{ErrorCode::malformed, "Invalid plugin recipe extent"};
        PluginImageIdentity identity;
        identity.api_version = 0;
        for (std::size_t i = 3; i < 7; ++i)
            identity.api_version = (identity.api_version << 8) | std::to_integer<unsigned>(bytes[i]);
        std::size_t position = 7;
        for (auto *text : {&identity.plugin_id, &identity.plugin_version, &identity.extension_id, &identity.format_id}) {
            if (bytes.size() - position < 2)
                return Error{ErrorCode::malformed, "Truncated plugin recipe identity"};
            const auto size = (std::to_integer<unsigned>(bytes[position]) << 8) |
                              std::to_integer<unsigned>(bytes[position + 1]);
            position += 2;
            if (!size || size >= 1024 || size > bytes.size() - position)
                return Error{ErrorCode::malformed, "Invalid plugin recipe identity extent"};
            text->assign(reinterpret_cast<const char *>(bytes.data() + position), size);
            position += size;
        }
        if (position != bytes.size() || !valid_plugin_identity(identity))
            return Error{ErrorCode::malformed, "Invalid plugin recipe identity or version"};
        LoadRecipe recipe{Format::plugin, {}};
        recipe.plugin = std::move(identity);
        return recipe;
    }
    if (bytes.size() == 3 && bytes[0] == std::byte{5} && bytes[1] == std::byte{0}) {
        if (bytes[2] == std::byte{8}) return LoadRecipe{Format::intel_hex, {}};
        if (bytes[2] == std::byte{9}) return LoadRecipe{Format::s_record, {}};
    }
    if (bytes.size() == 3 && (bytes[0] == std::byte{1} || bytes[0] == std::byte{4}) &&
        bytes[1] == std::byte{0} && bytes[2] == std::byte{11})
        return LoadRecipe{Format::wasm, {}};
    if (bytes.size() == 3 && (bytes[0] == std::byte{1} || bytes[0] == std::byte{4}) &&
        bytes[1] == std::byte{0} && bytes[2] == std::byte{12})
        return LoadRecipe{Format::dex, {}};
    if (bytes.size() == 3 && (bytes[0] == std::byte{1} || bytes[0] == std::byte{4}) &&
        bytes[1] == std::byte{0} && bytes[2] == std::byte{13})
        return LoadRecipe{Format::jvm, {}};
    if (bytes.size() == 3 && (bytes[0] == std::byte{1} || bytes[0] == std::byte{4}) &&
        bytes[1] == std::byte{0} && bytes[2] == std::byte{16})
        return LoadRecipe{Format::minidump, {}};
    if (bytes.size() >= 6 && bytes[0] == std::byte{2} && bytes[1] == std::byte{0} &&
        bytes[2] == std::byte{18}) {
        const auto count = (std::to_integer<unsigned>(bytes[3]) << 8) |
                           std::to_integer<unsigned>(bytes[4]);
        if (count > 128)
            return Error{ErrorCode::malformed, "Invalid Minidump PDB candidate count"};
        LoadRecipe recipe{Format::minidump, {}};
        const auto flags = std::to_integer<unsigned>(bytes[5]);
        if (flags > 1 || (!count && !flags))
            return Error{ErrorCode::malformed, "Invalid Minidump PDB recipe flags"};
        recipe.minidump_pdb_search_truncated = (flags & 1) != 0;
        std::size_t position = 6;
        std::size_t total_path_bytes = 0;
        for (unsigned index = 0; index < count; ++index) {
            if (bytes.size() - position < 4)
                return Error{ErrorCode::malformed, "Truncated Minidump PDB recipe path length"};
            std::uint64_t size = 0;
            for (std::size_t i = 0; i < 4; ++i) size = (size << 8) | std::to_integer<unsigned>(bytes[position++]);
            if (!size || size > 32768 || size > bytes.size() - position ||
                total_path_bytes > 1024 * 1024 - size)
                return Error{ErrorCode::malformed, "Invalid Minidump PDB recipe path extent"};
            total_path_bytes += static_cast<std::size_t>(size);
            std::u8string path;
            path.reserve(static_cast<std::size_t>(size));
            for (std::size_t i = 0; i < size; ++i)
                path.push_back(char8_t(std::to_integer<unsigned char>(bytes[position++])));
            auto decoded = std::filesystem::path(path);
            if (decoded.empty() || decoded.native().find(std::filesystem::path::value_type{}) != decoded.native().npos)
                return Error{ErrorCode::malformed, "Invalid Minidump PDB recipe path"};
            recipe.minidump_pdb_paths.push_back(std::move(decoded));
        }
        if (position != bytes.size())
            return Error{ErrorCode::malformed, "Trailing bytes in Minidump PDB recipe"};
        return recipe;
    }
    if (bytes.size() == 4 && bytes[0] == std::byte{1} && bytes[1] == std::byte{0} &&
        bytes[2] == std::byte{14}) {
        const auto target = std::to_integer<unsigned>(bytes[3]);
        if (target > static_cast<unsigned>(PeRuntimeArchitecture::x64_compatible))
            return Error{ErrorCode::malformed, "Invalid PE runtime architecture recipe"};
        LoadRecipe recipe{Format::pe, {}};
        recipe.pe_runtime_architecture = static_cast<PeRuntimeArchitecture>(target);
        return recipe;
    }
    if (bytes.size() >= 8 && bytes[0] == std::byte{2} && bytes[1] == std::byte{0} &&
        bytes[2] == std::byte{15}) {
        const auto target = std::to_integer<unsigned>(bytes[3]);
        if (target > static_cast<unsigned>(PeRuntimeArchitecture::x64_compatible))
            return Error{ErrorCode::malformed, "Invalid PE runtime architecture recipe"};
        std::uint64_t size = 0;
        for (std::size_t i = 4; i < 8; ++i)
            size = (size << 8) | std::to_integer<unsigned>(bytes[i]);
        if (size == 0 || size > 32768 || size != bytes.size() - 8)
            return Error{ErrorCode::malformed, "Invalid PE runtime/PDB recipe path extent"};
        std::u8string path;
        path.reserve(static_cast<std::size_t>(size));
        for (std::size_t i = 8; i < bytes.size(); ++i)
            path.push_back(char8_t(std::to_integer<unsigned char>(bytes[i])));
        auto decoded = std::filesystem::path(path);
        if (decoded.empty() || decoded.native().find(std::filesystem::path::value_type{}) != decoded.native().npos)
            return Error{ErrorCode::malformed, "Invalid PE runtime/PDB recipe path"};
        LoadRecipe recipe{Format::pe, {}, {}, std::move(decoded)};
        recipe.pe_runtime_architecture = static_cast<PeRuntimeArchitecture>(target);
        return recipe;
    }
    if (bytes.size() >= 3 && bytes[0] == std::byte{2} && bytes[1] == std::byte{0} && bytes[2] == std::byte{7}) {
        if (bytes.size() < 7) return Error{ErrorCode::malformed, "Truncated PE/PDB recipe"};
        std::uint64_t size = 0;
        for (std::size_t i = 3; i < 7; ++i) size = (size << 8) | std::to_integer<unsigned>(bytes[i]);
        if (size == 0 || size > 32768 || size != bytes.size() - 7)
            return Error{ErrorCode::malformed, "Invalid PE/PDB recipe path extent"};
        std::u8string path;
        path.reserve(static_cast<std::size_t>(size));
        for (std::size_t i = 7; i < bytes.size(); ++i) path.push_back(char8_t(std::to_integer<unsigned char>(bytes[i])));
        auto decoded = std::filesystem::path(path);
        if (decoded.empty() || decoded.native().find(std::filesystem::path::value_type{}) != decoded.native().npos)
            return Error{ErrorCode::malformed, "Invalid PE/PDB recipe path"};
        return LoadRecipe{Format::pe, {}, {}, std::move(decoded)};
    }
    if (bytes.size() >= 3 && bytes[0] == std::byte{3} && bytes[1] == std::byte{0} && bytes[2] == std::byte{6}) {
        if (bytes.size() < 7)
            return Error{ErrorCode::malformed, "Truncated ARM profile recipe"};
        std::uint64_t size = 0;
        for (std::size_t i = 3; i < 7; ++i)
            size = (size << 8) | std::to_integer<unsigned>(bytes[i]);
        if (size > arm_profile_text_limit || size != bytes.size() - 7)
            return Error{ErrorCode::malformed, "Invalid ARM profile recipe extent"};
        const std::string_view text(reinterpret_cast<const char *>(bytes.data() + 7), static_cast<std::size_t>(size));
        auto profile = parse_arm_profile(text);
        if (!profile)
            return profile.error();
        auto canonical = format_arm_profile(profile.value());
        if (!canonical)
            return canonical.error();
        if (canonical.value() != text)
            return Error{ErrorCode::malformed, "Durable ARM profile is not canonical"};
        auto raw = make_arm_raw_options(std::move(profile.value()));
        if (!raw)
            return raw.error();
        return LoadRecipe{Format::raw, std::move(raw.value())};
    }
    if (bytes.size() >= 3 && bytes[0] == std::byte{1} && bytes[1] == std::byte{0} && bytes[2] == std::byte{5}) {
        if (bytes.size() == 4 && bytes[3] == std::byte{0})
            return LoadRecipe{Format::macho, {}, {}};
        if (bytes.size() == 8 && bytes[3] == std::byte{1}) {
            std::uint32_t index = 0;
            for (std::size_t i = 4; i < 8; ++i)
                index = (index << 8) | std::to_integer<unsigned>(bytes[i]);
            return LoadRecipe{Format::macho, {}, MachOOptions{index}};
        }
        return Error{ErrorCode::malformed, "Invalid Mach-O recipe flags or extent"};
    }
    if (bytes.size() >= 3 && bytes[0] == std::byte{2} && bytes[1] == std::byte{0} && bytes[2] == std::byte{3}) {
        if (bytes.size() < 7)
            return Error{ErrorCode::malformed, "Truncated segmented recipe"};
        std::uint64_t size = 0;
        for (std::size_t i = 3; i < 7; ++i)
            size = (size << 8) | std::to_integer<unsigned>(bytes[i]);
        if (size > x86_profile_text_limit || size != bytes.size() - 7)
            return Error{ErrorCode::malformed, "Invalid segmented profile extent"};
        const std::string_view text(reinterpret_cast<const char *>(bytes.data() + 7), static_cast<std::size_t>(size));
        auto profile = parse_x86_profile(text);
        if (!profile)
            return profile.error();
        auto canonical = format_x86_profile(profile.value());
        if (!canonical)
            return canonical.error();
        if (canonical.value() != text)
            return Error{ErrorCode::malformed, "Durable segmented profile is not canonical"};
        auto raw = make_x86_raw_options(std::move(profile.value()));
        if (!raw)
            return raw.error();
        return LoadRecipe{Format::raw, std::move(raw.value())};
    }
    if (bytes.size() < 3 || (bytes[0] != std::byte{1} && bytes[0] != std::byte{4}) || bytes[1] != std::byte{0})
        return Error{ErrorCode::malformed, "Unknown or truncated load recipe version"};
    if (bytes[2] == std::byte{2} && bytes.size() == 3)
        return LoadRecipe{Format::pe, {}};
    if (bytes[2] == std::byte{4} && bytes.size() == 3)
        return LoadRecipe{Format::elf, {}};
    if (bytes[2] == std::byte{6} && bytes.size() == 3)
        return LoadRecipe{Format::ar, {}};
    const bool ordered_raw = bytes[0] == std::byte{4};
    if (bytes[2] != std::byte{1} || bytes.size() < 19)
        return Error{ErrorCode::malformed, "Invalid load recipe format or extent"};
    const auto get = [&](size_t offset, size_t width) {
        uint64_t value = 0;
        for (size_t i = 0; i < width; ++i)
            value = (value << 8) | std::to_integer<unsigned>(bytes[offset + i]);
        return value;
    };
    const auto flags = get(5, 1), has_entry = get(18, 1);
    if (flags > 7 || has_entry > 1 || bytes.size() != (has_entry ? 31 : 19) + (ordered_raw ? 1 : 0) ||
        (ordered_raw && get(bytes.size() - 1, 1) != 1))
        return Error{ErrorCode::malformed, "Invalid raw recipe flags or extent"};
    RawOptions raw{static_cast<Architecture>(get(3, 1)),
                   static_cast<ExecutionMode>(get(4, 1)),
                   {{static_cast<uint32_t>(get(6, 4))}, get(10, 8)},
                   bool(flags & 1),
                   bool(flags & 2),
                   bool(flags & 4),
                   {}};
    if (ordered_raw)
        raw.order = ByteOrder::big;
    if (has_entry)
        raw.entry = Address{{static_cast<uint32_t>(get(19, 4))}, get(23, 8)};
    LoadRecipe recipe{Format::raw, raw};
    if (!valid(recipe))
        return Error{ErrorCode::malformed, "Unknown architecture or mode in load recipe"};
    return recipe;
}
Result<LoadRecipe> resolve_load_recipe(const ByteStorage &storage, const LoadRecipe &recipe, std::stop_token stop) {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Image loading canceled"};
    if (recipe.plugin && recipe.format != Format::plugin)
        return Error{ErrorCode::invalid_argument, "Plugin identity requires an explicit plugin format"};
    if (recipe.format == Format::automatic && !recipe.raw) {
        auto plugin = probe_plugin_image(storage, stop);
        if (!plugin) return plugin.error();
        if (plugin.value()) {
            if (recipe.macho || recipe.pdb_path || recipe.pe_runtime_architecture ||
                recipe.dwarf_supplementary_package_path)
                return Error{ErrorCode::invalid_argument, "Built-in loader options cannot be applied to a plugin image"};
            LoadRecipe selected{Format::plugin, {}};
            selected.plugin = std::move(*plugin.value());
            return selected;
        }
        auto detected = detect_format(storage);
        if (!detected)
            return detected.error();
        if (recipe.pdb_path && detected.value() != DetectedFormat::pe_candidate)
            return Error{ErrorCode::invalid_argument, "A local PDB can only be selected for a PE input"};
        if (detected.value() == DetectedFormat::macho_candidate) {
            if (recipe.pe_runtime_architecture)
                return Error{ErrorCode::invalid_argument, "PE runtime architecture selection requires a PE input"};
            return resolve_load_recipe(storage, {Format::macho, {}, recipe.macho}, stop);
        }
        if (recipe.macho)
            return Error{ErrorCode::invalid_argument, "Slice options require a Mach-O input"};
        if (detected.value() == DetectedFormat::pe_candidate) {
            LoadRecipe selected{Format::pe, {}};
            selected.pdb_path = recipe.pdb_path;
            selected.pe_runtime_architecture = recipe.pe_runtime_architecture;
            return attach_adjacent_pe_pdb(storage, std::move(selected), stop);
        }
        if (recipe.pe_runtime_architecture)
            return Error{ErrorCode::invalid_argument, "PE runtime architecture selection requires a PE input"};
        if (detected.value() == DetectedFormat::elf_candidate) {
            LoadRecipe selected{Format::elf, {}};
            selected.dwarf_supplementary_package_path = recipe.dwarf_supplementary_package_path;
            return selected;
        }
        if (recipe.dwarf_supplementary_package_path)
            return Error{ErrorCode::invalid_argument, "DWARF supplementary package requires an ELF input"};
        if (detected.value() == DetectedFormat::wasm_candidate)
            return LoadRecipe{Format::wasm, {}};
        if (detected.value() == DetectedFormat::dex_candidate)
            return LoadRecipe{Format::dex, {}};
        if (detected.value() == DetectedFormat::jvm_candidate)
            return LoadRecipe{Format::jvm, {}};
        if (detected.value() == DetectedFormat::minidump_candidate)
            return LoadRecipe{Format::minidump, {}};
        if (detected.value() == DetectedFormat::ar_candidate)
            return LoadRecipe{Format::ar, {}};
        return Error{ErrorCode::unsupported, "Unknown format; choose raw with explicit architecture and base"};
    }
    if (!valid(recipe))
        return Error{ErrorCode::invalid_argument, "Invalid load recipe"};
    if (recipe.format == Format::macho) {
        auto container = read_macho_container(storage, stop);
        if (!container)
            return container.error();
        auto selected = macho_detail::select_slice(container.value(), recipe.macho.value_or(MachOOptions{}));
        if (!selected)
            return selected.error();
        return LoadRecipe{Format::macho,
                          {},
                          container.value().universal ? std::optional{MachOOptions{selected.value()}} : std::nullopt};
    }
    return attach_adjacent_pe_pdb(storage, recipe, stop);
}
Result<LoadedImage> load_image(std::shared_ptr<const ByteStorage> storage, const LoadRecipe &requested,
                               std::stop_token stop) {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Image loading canceled"};
    if (!storage)
        return Error{ErrorCode::invalid_argument, "Image loading requires byte storage"};
    const auto file_storage = std::dynamic_pointer_cast<const FileStorage>(storage);
    // Recipe detection and plugin probes can affect the selected image
    // provider just as parser reads affect metadata. Track both phases on one
    // source boundary so the durable LoadedImage retains the complete read set.
    auto tracking = TrackingStorage::create(std::move(storage));
    if (!tracking)
        return tracking.error();
    auto resolved = resolve_load_recipe(*tracking.value(), requested, stop);
    if (!resolved)
        return resolved.error();
    auto loaded = load_durable_image(tracking.value(), resolved.value(), stop);
    if (!loaded)
        return loaded.error();
    // DWARF .debug_sup filenames are untrusted hints. Automatic discovery is
    // limited to a basename-only supplementary ELF beside a file-backed
    // primary input; its role and checksum are validated before use.
    bool supplementary_selected = resolved.value().dwarf_supplementary_package_path.has_value();
    if (file_storage && !supplementary_selected &&
        loaded.value().metadata.elf &&
        loaded.value().metadata.elf->dwarf_supplementary_identity &&
        !loaded.value().metadata.elf->dwarf_supplementary_identity->supplementary) {
        const auto &identity = *loaded.value().metadata.elf->dwarf_supplementary_identity;
        const auto candidate = discover_local_supplementary_dwp(file_storage->backing_path(), identity);
        if (candidate) {
            auto discovered = resolved.value();
            discovered.dwarf_supplementary_package_path = *candidate;
            auto supplemented = load_durable_image(tracking.value(), discovered, stop);
            if (!supplemented) return supplemented.error();
            loaded = std::move(supplemented);
            supplementary_selected = true;
        }
    }
    // Split-package discovery uses only the primary input's basename plus
    // `.dwp`; DW_AT_dwo_name and DW_AT_comp_dir are never used as paths.
    if (file_storage && resolved.value().format == Format::elf &&
        !resolved.value().dwarf_supplementary_package_path && !supplementary_selected) {
        const auto candidate = discover_local_split_dwp(file_storage->backing_path());
        bool split_package_selected = false;
        if (candidate) {
            auto package = FileStorage::open(*candidate);
            if (!package) return package.error();
            if (package.value()->size() > UINT64_C(64) * 1024 * 1024)
                return Error{ErrorCode::resource_limit, "Discovered ELF DWP exceeds 64 MiB"};
            ElfLoadOptions options;
            options.dwarf_split_debug_package = std::move(package.value());
            auto split = load_elf(tracking.value(), options, stop);
            if (!split) return split.error();
            loaded = std::move(split);
            split_package_selected = true;
        }
        // If there is no adjacent DWP, allow the bounded caller-scoped DWO
        // resolver to try the basename named by each skeleton. The resolver
        // rejects path components, symlinks, duplicate IDs, and oversized
        // files; import_elf_dwo then verifies the exact DWO ID and address
        // size before accepting any contribution. This remains offline.
        if (!split_package_selected) {
            std::error_code source_error;
            const auto source = std::filesystem::canonical(file_storage->backing_path(), source_error);
            if (source_error) return Error{ErrorCode::io, "Cannot canonicalize ELF input for DWO discovery: " + source_error.message()};
            auto resolver = make_elf_dwo_directory_resolver(source.parent_path(), stop);
            if (!resolver) return resolver.error();
            Sha256 identity_hash;
            constexpr std::string_view resolver_domain = "HexLab/automatic-ELF-DWO-directory/v1";
            auto hashed = identity_hash.update(std::as_bytes(std::span(resolver_domain.data(), resolver_domain.size())));
            if (!hashed) return hashed.error();
            const auto root = source.parent_path().generic_string();
            hashed = identity_hash.update(std::as_bytes(std::span(root.data(), root.size())));
            if (!hashed) return hashed.error();
            ElfLoadOptions options;
            options.dwarf_split_resolver = std::move(resolver.value());
            options.dwarf_split_resolver_identity = identity_hash.digest();
            auto split = load_elf(tracking.value(), options, stop);
            if (!split) return split.error();
            loaded = std::move(split);
        }
    }
    loaded.value().metadata_reads = tracking.value()->reads();
    return loaded;
}
Result<LoadedImage> load_durable_image(std::shared_ptr<const ByteStorage> storage, const LoadRecipe &recipe,
                                       std::stop_token stop) {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Image loading canceled"};
    if (!storage)
        return Error{ErrorCode::invalid_argument, "Image loading requires byte storage"};
    if (!valid(recipe))
        return Error{ErrorCode::invalid_argument, "A concrete durable load recipe is required"};
    if (recipe.plugin)
        return load_plugin(std::move(storage), *recipe.plugin, stop);
    if (recipe.format == Format::intel_hex || recipe.format == Format::s_record) {
        // Source file offsets address record text, while the image uses decoded
        // packed bytes. All text bytes participate in parser invalidation.
        if (storage->size() > UINT64_C(1024) * 1024 * 1024 || storage->size() > SIZE_MAX)
            return Error{ErrorCode::resource_limit, "Firmware text exceeds the 1 GiB input limit"};
        auto view = storage->read_at({0}, static_cast<std::size_t>(storage->size()));
        if (!view) return view.error();
        if (view.value().bytes.size() != storage->size())
            return Error{ErrorCode::io, "Firmware source returned an incomplete read"};
        const auto text = std::string_view(reinterpret_cast<const char *>(view.value().bytes.data()),
                                           view.value().bytes.size());
        auto loaded = load_firmware(text, FirmwareLoadOptions{recipe.format == Format::intel_hex
            ? firmware::Format::intel_hex : firmware::Format::motorola_s_record}, stop);
        if (!loaded) return loaded.error();
        auto dependency = loaded.value().metadata_reads.include({0}, storage->size());
        if (!dependency) return dependency.error();
        loaded.value().metadata_reads_complete = true;
        return loaded;
    }
    if (recipe.format == Format::pe) {
        auto loaded = load_pe(std::move(storage), stop);
        if (!loaded) return loaded.error();
        if (recipe.pe_runtime_architecture) {
            auto selected = select_pe_runtime_view(loaded.value(), *recipe.pe_runtime_architecture);
            if (!selected) return selected.error();
            loaded.value().image = std::move(selected.value());
            loaded.value().pe_runtime_target = recipe.pe_runtime_architecture;
        }
        if (recipe.pdb_path) {
            auto bound = bind_local_pe_pdb(loaded.value(), *recipe.pdb_path, stop);
            if (!bound) return bound.error();
            // PDB binding reads a separate file whose byte dependencies are
            // not represented by the PE source's ReadSet.
            loaded.value().metadata_reads_complete = false;
        }
        return loaded;
    }
    if (recipe.format == Format::elf) {
        if (!recipe.dwarf_supplementary_package_path)
            return load_elf(std::move(storage), stop);
        auto package = FileStorage::open(*recipe.dwarf_supplementary_package_path);
        if (!package) return package.error();
        ElfLoadOptions options;
        options.dwarf_supplementary_package = std::move(package.value());
        auto loaded = load_elf(std::move(storage), options, stop);
        if (!loaded) return loaded.error();
        auto package_hash = hash_source(*options.dwarf_supplementary_package, stop);
        if (!package_hash) return package_hash.error();
        loaded.value().external_input_fingerprint =
            combine_external_fingerprints(loaded.value().external_input_fingerprint, package_hash.value());
        return loaded;
    }
    if (recipe.format == Format::macho)
        return macho_detail::load_macho_bound(std::move(storage), recipe.macho.value_or(MachOOptions{}),
                                              recipe.macho && recipe.macho->slice_index.has_value(), stop);
    if (recipe.format == Format::wasm)
        return load_wasm(std::move(storage), stop);
    if (recipe.format == Format::dex)
        return load_dex(std::move(storage), stop);
    if (recipe.format == Format::jvm)
        return load_jvm_class(std::move(storage), stop);
    if (recipe.format == Format::minidump) {
        auto loaded = load_minidump(std::move(storage), stop);
        if (!loaded) return loaded.error();
        if (!recipe.minidump_pdb_paths.empty()) {
            std::vector<MinidumpPdbCandidate> candidates;
            candidates.reserve(recipe.minidump_pdb_paths.size());
            for (const auto &path : recipe.minidump_pdb_paths)
                candidates.push_back({std::nullopt, path});
            auto bound = bind_local_minidump_pdbs(loaded.value(), candidates, stop);
            if (!bound) return bound.error();
        }
        if (recipe.minidump_pdb_search_truncated && loaded.value().metadata.minidump) {
            for (auto &module : loaded.value().metadata.minidump->modules) {
                if (module.codeview_kind == "RSDS" && module.pdb_status == MinidumpPdbStatus::unavailable)
                    module.pdb_diagnostic = "PDB sidecar search was truncated at the 128 candidate path limit";
            }
        }
        return loaded;
    }
    if (recipe.format == Format::ar)
        return Error{ErrorCode::unsupported, "ar archives have no single image; use load_archive and select a member"};
    auto image = load_raw(storage, *recipe.raw, stop);
    if (!image)
        return image.error();
    LoadedImage loaded;
    loaded.image = std::move(image.value());
    loaded.metadata.format = "raw";
    loaded.metadata_complete = true;
    loaded.metadata_reads_complete = true;
    loaded.metadata.preferred_base =
        recipe.raw->x86_profile ? recipe.raw->x86_profile->input_load_address : recipe.raw->base.offset;
    loaded.metadata.image_size = storage->size();
    return loaded;
}
Result<LoadedArchive> load_archive(std::shared_ptr<const ByteStorage> storage, const LoadRecipe &requested,
                                   std::stop_token stop, ArLimits limits) {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Archive loading canceled"};
    if (!storage)
        return Error{ErrorCode::invalid_argument, "Archive loading requires byte storage"};
    auto recipe = resolve_load_recipe(*storage, requested, stop);
    if (!recipe)
        return recipe.error();
    if (recipe.value().format != Format::ar)
        return Error{ErrorCode::invalid_argument, "Load recipe does not select an ar archive"};
    auto archive = read_ar_archive(*storage, stop, limits);
    if (!archive)
        return archive.error();
    return LoadedArchive{std::move(storage), std::move(archive.value())};
}
} // namespace hexlab
