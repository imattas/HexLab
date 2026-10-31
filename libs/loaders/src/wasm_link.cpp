#include "hexlab/loaders/wasm.hpp"

#include <algorithm>
#include <limits>

namespace hexlab {
namespace {
bool known_kind(WasmExternalKind k) {
    return k == WasmExternalKind::function || k == WasmExternalKind::table ||
           k == WasmExternalKind::memory || k == WasmExternalKind::global;
}
bool limits_match(const WasmLimits &need, const WasmLimits &have) {
    if (need.shared != have.shared || have.minimum < need.minimum) return false;
    if (need.maximum && (!have.maximum || *have.maximum > *need.maximum)) return false;
    return true;
}
}

std::vector<WasmLinkResolution> link_wasm_inventory(std::span<const WasmLinkModule> modules,
                                                    WasmLinkOptions options, std::stop_token stop) {
    std::vector<WasmLinkResolution> out;
    std::size_t import_count = 0;
    bool inventory_ok = modules.size() <= options.maximum_modules;
    for (const auto &m : modules) {
        if (m.identity.empty() || m.identity.size() > 4096 || !m.metadata) inventory_ok = false;
        if (m.metadata) {
            if (m.metadata->imports.size() > options.maximum_imports - std::min(import_count, options.maximum_imports)) inventory_ok = false;
            else import_count += m.metadata->imports.size();
        }
    }
    for (std::size_t i = 0; i < modules.size(); ++i)
        for (std::size_t j = i + 1; j < modules.size(); ++j)
            if (modules[i].identity == modules[j].identity) inventory_ok = false;
    if (!inventory_ok) {
        out.push_back({{}, {}, {}, WasmExternalKind::function, WasmLinkStatus::invalid_inventory, {}, {},
                       "module inventory is null, unnamed, duplicated, or exceeds configured bounds"});
        return out;
    }
    for (std::size_t mi = 0, comparisons = 0; mi < modules.size(); ++mi) {
        const auto &consumer = modules[mi];
        for (const auto &imp : consumer.metadata->imports) {
            if (stop.stop_requested()) return out;
            WasmLinkResolution row{consumer.identity, imp.module, imp.name, imp.kind};
            if (!known_kind(imp.kind)) {
                row.status = WasmLinkStatus::unsupported; row.detail = "import kind is not represented by this metadata version";
                out.push_back(std::move(row)); continue;
            }
            std::size_t hits = 0; const WasmLinkModule *provider = nullptr; const WasmExport *exp = nullptr;
            bool budget_exhausted = false;
            for (std::size_t pi = 0; pi < modules.size(); ++pi) {
                if (pi == mi || modules[pi].identity == consumer.identity) continue;
                for (const auto &candidate : modules[pi].metadata->exports) {
                    if (++comparisons > options.maximum_export_comparisons) { budget_exhausted = true; break; }
                    if (candidate.name == imp.name && candidate.kind == imp.kind && modules[pi].identity == imp.module) {
                        ++hits; provider = &modules[pi]; exp = &candidate;
                    }
                }
                if (budget_exhausted) break;
            }
            if (budget_exhausted) { row.status = WasmLinkStatus::unsupported; row.detail = "export comparison budget exhausted"; out.push_back(std::move(row)); continue; }
            if (!hits) { row.status = WasmLinkStatus::missing; row.detail = "no supplied module exports the requested module/name/kind"; out.push_back(std::move(row)); continue; }
            if (hits != 1) { row.status = WasmLinkStatus::ambiguous; row.detail = "multiple supplied exports match the requested module/name/kind"; out.push_back(std::move(row)); continue; }
            row.provider = provider->identity; row.provider_export_index = exp->index;
            bool compatible = false;
            switch (imp.kind) {
            case WasmExternalKind::function:
                if (!imp.function_type_index || *imp.function_type_index >= consumer.metadata->function_types.size() ||
                    !exp->function_type_index || *exp->function_type_index >= provider->metadata->function_types.size()) {
                    row.status = WasmLinkStatus::unsupported; row.detail = "function signature metadata is incomplete";
                    out.push_back(std::move(row)); continue;
                }
                compatible = consumer.metadata->function_types[*imp.function_type_index] == provider->metadata->function_types[*exp->function_type_index];
                break;
            case WasmExternalKind::table:
            case WasmExternalKind::memory:
                if (!imp.limits || !exp->limits) { row.status = WasmLinkStatus::unsupported; row.detail = "limits metadata is incomplete"; out.push_back(std::move(row)); continue; }
                compatible = limits_match(*imp.limits, *exp->limits);
                break;
            case WasmExternalKind::global:
                if (!imp.global_value_type || !exp->global_value_type) { row.status = WasmLinkStatus::unsupported; row.detail = "global type metadata is incomplete"; out.push_back(std::move(row)); continue; }
                compatible = imp.global_value_type == exp->global_value_type && imp.global_mutable == exp->global_mutable;
                break;
            }
            row.status = compatible ? WasmLinkStatus::linked : WasmLinkStatus::incompatible;
            row.detail = compatible ? "metadata types are compatible; no runtime binding was created" : "provider export type does not satisfy import type";
            out.push_back(std::move(row));
        }
    }
    return out;
}
}
