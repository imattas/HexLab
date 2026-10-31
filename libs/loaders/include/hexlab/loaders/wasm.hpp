#pragma once
#include "hexlab/loaders/loaded_image.hpp"
#include <memory>
#include <functional>
#include <optional>
#include <stop_token>
#include <string>
#include <span>

namespace hexlab {
// Bounded WebAssembly v1 container/function-body loader. It retains import and
// export metadata and maps each defined function's operator stream into its own
// zero-based address domain so branch depths and instruction locations remain
// function-relative. Statically reconstructible initial linear memory is
// mapped in a distinct wasm32 address space.
// Resolver returns exact raw bits for numeric imported globals. Returning
// nullopt leaves that import unresolved. Funcref globals remain metadata-only.
// The callback runs only after module/body validation.
using WasmGlobalImportResolver = std::function<std::optional<std::uint64_t>(const WasmImport &)>;
struct WasmFunctionHostBinding {
    std::string symbol;
    WasmFunctionType type;
};
using WasmFunctionImportResolver = std::function<std::optional<WasmFunctionHostBinding>(const WasmImport &)>;
// Optional compatibility facts for imported tables and memories. Table facts
// provide the element reference type and limits; memory facts provide limits
// and whether the host object uses memory64. `binding` is an optional bounded
// symbolic label retained for analysis, not an executable/runtime binding.
struct WasmImportHostFacts {
    std::string binding;
    std::optional<WasmLimits> limits;
    std::optional<std::uint8_t> table_reference_type;
    bool memory64 = false;
};
using WasmTableMemoryImportResolver = std::function<std::optional<WasmImportHostFacts>(const WasmImport &)>;

// Offline module inventory linking. This compares only caller-supplied parsed
// metadata; it never opens files, loads modules, or executes host code.
struct WasmLinkModule {
    std::string identity;
    const WasmMetadata *metadata = nullptr;
};
enum class WasmLinkStatus : std::uint8_t { linked, missing, ambiguous, incompatible, unsupported, invalid_inventory };
struct WasmLinkResolution {
    std::string consumer, module, name;
    WasmExternalKind kind = WasmExternalKind::function;
    WasmLinkStatus status = WasmLinkStatus::missing;
    std::optional<std::string> provider;
    std::optional<std::uint32_t> provider_export_index;
    std::string detail;
};
struct WasmLinkOptions {
    std::size_t maximum_modules = 4096;
    std::size_t maximum_imports = 1'000'000;
    std::size_t maximum_export_comparisons = 16'000'000;
};
HEXLAB_LOADERS_EXPORT std::vector<WasmLinkResolution> link_wasm_inventory(
    std::span<const WasmLinkModule>, WasmLinkOptions = {}, std::stop_token = {});
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_wasm(std::shared_ptr<const ByteStorage>, std::stop_token,
                                                    WasmGlobalImportResolver = {},
                                                    WasmTableMemoryImportResolver = {},
                                                    WasmFunctionImportResolver = {});
}
