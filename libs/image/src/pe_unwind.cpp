#include "hexlab/image/pe_unwind.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <string_view>

namespace hexlab {
namespace {
constexpr std::size_t max_unwind_operations = 512;
constexpr std::size_t max_unwind_depth = 32;
constexpr std::size_t max_fh4_metadata_records = 1'000'000;
constexpr std::size_t max_fh4_name_bytes = 1024 * 1024;

Error failure(ErrorCode code, std::string message) { return {code, std::move(message)}; }

Result<std::uint64_t> scalar(const PeRegisterContext &context, std::string_view name) {
    const auto it = context.registers.find(name);
    if (it == context.registers.end()) return failure(ErrorCode::invalid_argument, "missing register " + std::string(name));
    if (it->second.size() != 8) return failure(ErrorCode::malformed, "register " + std::string(name) + " must contain 8 bytes");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(it->second[i])) << (i * 8);
    return value;
}

void put_scalar(PeRegisterContext &context, std::string_view name, std::uint64_t value) {
    auto &bytes = context.registers[std::string(name)];
    bytes.resize(8);
    for (std::size_t i = 0; i < 8; ++i) bytes[i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
}

Result<std::uint64_t> add(std::uint64_t a, std::uint64_t b) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a)
        return failure(ErrorCode::overflow, "PE unwind address arithmetic overflow");
    return a + b;
}

Result<std::vector<std::byte>> read_exact(const PeMemoryReader &reader, std::uint64_t address, std::size_t size) {
    if (!reader) return failure(ErrorCode::invalid_argument, "PE unwind memory reader is empty");
    if (size == 0 || size > 256) return failure(ErrorCode::resource_limit, "PE unwind memory read exceeds the scalar/SVE-vector bound");
    auto result = reader(address, size);
    if (!result) return result.error();
    if (result.value().size() != size) return failure(ErrorCode::out_of_bounds, "PE unwind memory reader returned a short read");
    return result.value();
}

Result<std::uint64_t> read64(const PeMemoryReader &reader, std::uint64_t address) {
    auto bytes = read_exact(reader, address, 8);
    if (!bytes) return bytes.error();
    std::uint64_t result = 0;
    for (std::size_t i = 0; i < 8; ++i) result |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes.value()[i])) << (i * 8);
    return result;
}

constexpr std::array<std::string_view, 16> amd64_names{
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};

Result<bool> restore_amd64_info(const PeUnwindInfo &info, PeRegisterContext &out,
                                const PeMemoryReader &memory, std::size_t depth,
                                std::optional<std::uint8_t> completed_prolog_offset = std::nullopt) {
    if (depth >= max_unwind_depth) return failure(ErrorCode::resource_limit, "AMD64 chained unwind depth exceeds 32");
    if (info.operations.size() > max_unwind_operations)
        return failure(ErrorCode::resource_limit, "AMD64 unwind operation count exceeds 512");
    auto rsp_result = scalar(out, "rsp");
    if (!rsp_result) return rsp_result.error();
    auto rsp = rsp_result.value();
    for (const auto &op : info.operations) {
        if (completed_prolog_offset && op.code_offset > *completed_prolog_offset) continue;
        switch (op.kind) {
        case PeUnwindOperationKind::push_nonvolatile: {
            if (op.register_number >= amd64_names.size() || op.register_number == 4)
                return failure(ErrorCode::malformed, "AMD64 unwind push names an invalid nonvolatile register");
            auto value = read64(memory, rsp); if (!value) return value.error();
            put_scalar(out, amd64_names[op.register_number], value.value());
            auto next = add(rsp, 8); if (!next) return next.error(); rsp = next.value();
            break;
        }
        case PeUnwindOperationKind::allocate_stack: {
            auto next = add(rsp, op.stack_size); if (!next) return next.error(); rsp = next.value();
            break;
        }
        case PeUnwindOperationKind::set_frame_pointer: {
            if (info.frame_register == 0 || info.frame_register >= amd64_names.size())
                return failure(ErrorCode::malformed, "AMD64 frame-register unwind has no valid frame register");
            auto frame = scalar(out, amd64_names[info.frame_register]); if (!frame) return frame.error();
            const auto distance = static_cast<std::uint64_t>(info.frame_offset) * 16;
            if (frame.value() < distance) return failure(ErrorCode::overflow, "AMD64 frame-register stack underflow");
            rsp = frame.value() - distance;
            break;
        }
        case PeUnwindOperationKind::save_nonvolatile: {
            if (op.register_number >= amd64_names.size() || op.register_number == 4)
                return failure(ErrorCode::malformed, "AMD64 unwind save names an invalid nonvolatile register");
            auto address = add(rsp, op.stack_offset); if (!address) return address.error();
            auto value = read64(memory, address.value()); if (!value) return value.error();
            put_scalar(out, amd64_names[op.register_number], value.value());
            break;
        }
        case PeUnwindOperationKind::save_xmm128: {
            if (op.register_number < 6 || op.register_number > 15)
                return failure(ErrorCode::malformed, "AMD64 unwind XMM save names a volatile or invalid register");
            auto address = add(rsp, op.stack_offset); if (!address) return address.error();
            auto value = read_exact(memory, address.value(), 16); if (!value) return value.error();
            out.registers["xmm" + std::to_string(op.register_number)] = std::move(value.value());
            break;
        }
        case PeUnwindOperationKind::push_machine_frame: {
            const auto rip_offset = op.machine_frame_has_error_code ? 8u : 0u;
            auto rip_address = add(rsp, rip_offset); if (!rip_address) return rip_address.error();
            auto rip = read64(memory, rip_address.value()); if (!rip) return rip.error();
            auto caller_sp = add(rsp, op.machine_frame_has_error_code ? 48u : 40u);
            if (!caller_sp) return caller_sp.error();
            put_scalar(out, "rip", rip.value()); rsp = caller_sp.value();
            break;
        }
        }
    }
    put_scalar(out, "rsp", rsp);
    if (info.chained_function) {
        if (!info.chained_function->unwind_info)
            return failure(ErrorCode::malformed, "AMD64 chained runtime function has no decoded unwind info");
        auto chained = restore_amd64_info(*info.chained_function->unwind_info, out, memory, depth + 1);
        if (!chained) return chained.error();
    }
    return true;
}

Result<PeRegisterContext> unwind_amd64(const PeMetadata &metadata, std::uint64_t base,
                                       std::uint64_t ip, const PeRegisterContext &input,
                                       const PeMemoryReader &memory) {
    if (ip < base || ip - base > std::numeric_limits<std::uint32_t>::max())
        return failure(ErrorCode::out_of_bounds, "instruction pointer is outside the PE RVA range");
    const auto rva = static_cast<std::uint32_t>(ip - base);
    const PeRuntimeFunction *match = nullptr;
    for (const auto &function : metadata.exception_functions)
        if (function.begin_rva <= rva && rva < function.end_rva) { match = &function; break; }
    if (!match || !match->unwind_info) return failure(ErrorCode::out_of_bounds, "no decoded AMD64 runtime function covers the instruction pointer");
    PeRegisterContext out = input;
    const auto function_offset = static_cast<std::uint64_t>(rva - match->begin_rva);
    const auto completed_prolog = function_offset < match->unwind_info->size_of_prolog
                                      ? std::optional<std::uint8_t>(static_cast<std::uint8_t>(function_offset))
                                      : std::nullopt;
    auto applied = restore_amd64_info(*match->unwind_info, out, memory, 0, completed_prolog);
    if (!applied) return applied.error();
    auto rsp = scalar(out, "rsp"); if (!rsp) return rsp.error();
    const bool machine_frame = std::any_of(match->unwind_info->operations.begin(), match->unwind_info->operations.end(),
        [&](const PeUnwindOperation &op) { return op.kind == PeUnwindOperationKind::push_machine_frame &&
            (!completed_prolog || op.code_offset <= *completed_prolog); });
    if (machine_frame) return out;
    auto return_ip = read64(memory, rsp.value()); if (!return_ip) return return_ip.error();
    auto caller_sp = add(rsp.value(), 8); if (!caller_sp) return caller_sp.error();
    put_scalar(out, "rsp", caller_sp.value()); put_scalar(out, "rip", return_ip.value());
    return out;
}

Result<PeRegisterContext> unwind_arm64(const PeMetadata &metadata, std::uint64_t base,
                                       std::uint64_t ip, const PeRegisterContext &input,
                                       const PeMemoryReader &memory, std::size_t depth = 0) {
    if (depth >= max_unwind_depth) return failure(ErrorCode::resource_limit, "ARM64 pdata parent-link depth exceeds 32");
    if (ip < base || ip - base > std::numeric_limits<std::uint32_t>::max())
        return failure(ErrorCode::out_of_bounds, "instruction pointer is outside the PE RVA range");
    const auto rva = static_cast<std::uint32_t>(ip - base);
    const PeArm64RuntimeFunction *match = nullptr;
    std::uint64_t match_end = 0;
    for (std::size_t i = 0; i < metadata.arm64_exception_functions.size(); ++i) {
        const auto &function = metadata.arm64_exception_functions[i];
        std::uint64_t end = static_cast<std::uint64_t>(function.begin_rva) + function.function_length;
        if (function.kind == PeArm64UnwindKind::pdata_link && function.function_length == 0) {
            for (std::size_t next = i + 1; next < metadata.arm64_exception_functions.size(); ++next)
                if (metadata.arm64_exception_functions[next].begin_rva > function.begin_rva) {
                    end = metadata.arm64_exception_functions[next].begin_rva; break;
                }
            if (end <= function.begin_rva) end = static_cast<std::uint64_t>(function.begin_rva) + 1;
        }
        if (function.begin_rva <= rva && rva < end) { match = &function; match_end = end; break; }
    }
    if (!match) return failure(ErrorCode::out_of_bounds, "no decoded ARM64 runtime function covers the instruction pointer");
    if (match->kind == PeArm64UnwindKind::pdata_link) {
        std::vector<bool> visited(metadata.arm64_exception_functions.size(), false);
        const PeArm64RuntimeFunction *parent = match;
        for (std::size_t links = 0; parent->kind == PeArm64UnwindKind::pdata_link; ++links) {
            if (links >= max_unwind_depth) return failure(ErrorCode::resource_limit, "ARM64 pdata parent-link depth exceeds 32");
            if (!parent->linked_record_index || *parent->linked_record_index >= metadata.arm64_exception_functions.size())
                return failure(ErrorCode::malformed, "ARM64 pdata parent link has an invalid target index");
            const auto target = *parent->linked_record_index;
            if (visited[target]) return failure(ErrorCode::malformed, "ARM64 pdata parent links contain a cycle");
            visited[target] = true;
            parent = &metadata.arm64_exception_functions[target];
        }
        PeMetadata resolved;
        auto normalized = *parent;
        normalized.begin_rva = match->begin_rva;
        normalized.function_length = static_cast<std::uint32_t>(match_end - match->begin_rva);
        resolved.arm64_exception_functions.push_back(std::move(normalized));
        return unwind_arm64(resolved, base, ip, input, memory, depth + 1);
    }
    PeRegisterContext out = input;
    auto sp_result = scalar(out, "sp"); if (!sp_result) return sp_result.error();
    auto sp = sp_result.value();
    if (match->packed_unwind) {
        const auto &packed = *match->packed_unwind;
        if (packed.cr == 2) return failure(ErrorCode::unsupported, "ARM64 packed CR=2 requires pointer-authentication keys to authenticate LR");
        if (packed.cr > 3) return failure(ErrorCode::malformed, "ARM64 packed unwind CR is invalid");
        const std::uint64_t frame_bytes = static_cast<std::uint64_t>(packed.frame_size) * 16;
        if (frame_bytes == 0) return failure(ErrorCode::malformed, "ARM64 packed unwind has an empty frame");
        const auto int_bytes = static_cast<std::uint64_t>(packed.reg_i) * 8 + (packed.cr == 1 ? 8 : 0);
        const auto fp_bytes = packed.reg_f ? static_cast<std::uint64_t>(packed.reg_f + 1) * 8 : 0;
        const auto save_bytes = (int_bytes + fp_bytes + (packed.homes_parameters ? 64 : 0) + 15) & ~std::uint64_t{15};
        if (save_bytes > frame_bytes) return failure(ErrorCode::malformed, "ARM64 packed save area exceeds frame size");
        const auto local_bytes = frame_bytes - save_bytes;
        auto int_at = add(sp, local_bytes); if (!int_at) return int_at.error();
        for (std::uint8_t n = 0; n < packed.reg_i; ++n) {
            auto at = add(int_at.value(), static_cast<std::uint64_t>(n) * 8); if (!at) return at.error();
            auto value = read64(memory, at.value()); if (!value) return value.error();
            put_scalar(out, "x" + std::to_string(19 + n), value.value());
        }
        if (packed.cr == 1) {
            auto lr_at = add(int_at.value(), static_cast<std::uint64_t>(packed.reg_i) * 8); if (!lr_at) return lr_at.error();
            auto lr = read64(memory, lr_at.value()); if (!lr) return lr.error(); put_scalar(out, "lr", lr.value());
        } else if (packed.cr == 3) {
            auto pair_at = Result<std::uint64_t>(sp);
            auto fp = read64(memory, pair_at.value()); if (!fp) return fp.error();
            auto lr_at = add(pair_at.value(), 8); if (!lr_at) return lr_at.error();
            auto lr = read64(memory, lr_at.value()); if (!lr) return lr.error();
            put_scalar(out, "fp", fp.value()); put_scalar(out, "lr", lr.value());
        }
        if (packed.reg_f) {
            const auto fp_at = add(int_at.value(), int_bytes); if (!fp_at) return fp_at.error();
            for (std::uint8_t n = 0; n <= packed.reg_f; ++n) {
                auto at = add(fp_at.value(), static_cast<std::uint64_t>(n) * 8); if (!at) return at.error();
                auto value = read_exact(memory, at.value(), 8); if (!value) return value.error();
                out.registers["d" + std::to_string(8 + n)] = std::move(value.value());
            }
        }
        auto next = add(sp, frame_bytes); if (!next) return next.error(); sp = next.value();
    } else if (match->xdata) {
        const auto &codes = match->xdata->unwind_codes;
        if (codes.size() > max_unwind_operations) return failure(ErrorCode::resource_limit, "ARM64 unwind operation count exceeds 512");
        std::size_t code_start = 0;
        std::size_t skip_codes = 0;
        const auto function_offset = static_cast<std::uint64_t>(rva - match->begin_rva);
        auto code_index_for_byte_offset = [&](std::uint16_t wanted) -> std::optional<std::size_t> {
            std::size_t offset = 0;
            for (std::size_t i = 0; i < codes.size(); ++i) {
                if (offset == wanted) return i;
                offset += codes[i].encoding.size();
            }
            return std::nullopt;
        };
        bool in_epilog = false;
        std::uint64_t epilog_offset = 0;
        std::optional<std::uint16_t> epilog_index;
        for (const auto &scope : match->xdata->epilog_scopes) {
            const auto start = code_index_for_byte_offset(scope.unwind_code_index);
            std::size_t length = 0;
            if (start) for (std::size_t i = *start; i < codes.size() && codes[i].opcode != 0xe4; ++i) ++length;
            if (start && function_offset >= scope.start_offset &&
                function_offset < std::uint64_t{scope.start_offset} + length * 4) {
                in_epilog = true; epilog_offset = function_offset - scope.start_offset;
                epilog_index = scope.unwind_code_index; break;
            }
        }
        if (match->xdata->single_epilog && match->xdata->epilog_count != 0) {
            const auto idx = match->xdata->epilog_count;
            auto found = code_index_for_byte_offset(idx);
            if (found) {
                std::size_t instruction_count = 0;
                for (std::size_t i = *found; i < codes.size() && codes[i].opcode != 0xe4; ++i) ++instruction_count;
                const auto inferred_start = std::uint64_t{match->function_length} - instruction_count * 4;
                if (function_offset >= inferred_start && function_offset < match->function_length) {
                    in_epilog = true; epilog_offset = function_offset - inferred_start; epilog_index = idx;
                }
            }
        }
        std::vector<const PeArm64UnwindCode *> active_codes;
        if (in_epilog && epilog_index) {
            auto found = code_index_for_byte_offset(*epilog_index);
            if (!found) return failure(ErrorCode::malformed, "ARM64 epilog scope does not identify an unwind-code boundary");
            code_start = *found; skip_codes = static_cast<std::size_t>(epilog_offset / 4);
            for (std::size_t i = code_start; i < codes.size(); ++i) {
                if (codes[i].opcode == 0xe4) { active_codes.push_back(&codes[i]); break; }
                active_codes.push_back(&codes[i]);
            }
        } else {
            std::size_t prolog_end = 0;
            while (prolog_end < codes.size() && codes[prolog_end].opcode != 0xe4 && codes[prolog_end].opcode != 0xe5) ++prolog_end;
            if (function_offset < prolog_end * 4) {
                const auto completed = std::min<std::size_t>(static_cast<std::size_t>(function_offset / 4), prolog_end);
                const auto first = prolog_end - completed;
                for (std::size_t i = first; i < prolog_end; ++i) active_codes.push_back(&codes[i]);
            } else {
                for (std::size_t i = 0; i < codes.size(); ++i) {
                    if (codes[i].opcode == 0xe4) { active_codes.push_back(&codes[i]); break; }
                    active_codes.push_back(&codes[i]);
                }
            }
        }
        if (skip_codes > active_codes.size()) return failure(ErrorCode::malformed, "ARM64 epilog PC advances beyond its unwind sequence");
        enum class PreviousPair { none, integer, floating } previous_pair = PreviousPair::none;
        std::uint8_t previous_pair_register = 0;
        std::uint64_t previous_pair_address = 0;
        for (std::size_t active = skip_codes; active < active_codes.size(); ++active) {
            const auto &code = *active_codes[active];
            if (code.encoding.empty()) return failure(ErrorCode::malformed, "ARM64 unwind operation has empty encoding");
            const auto op = code.encoding[0];
            const bool pair_sequence = (op >= 0x20 && op <= 0x3f) ||
                (op >= 0xc8 && op <= 0xcf) || (op >= 0xd8 && op <= 0xdb) ||
                (op == 0xe7 && code.encoding.size() == 3 && (code.encoding[1] & 0x40) != 0 &&
                 (code.encoding[2] >> 6) <= 2);
            if (op != 0xe6 && !pair_sequence) previous_pair = PreviousPair::none;
            auto restore_x = [&](std::uint8_t reg, std::uint64_t at) -> Result<bool> {
                if (reg > 30) return failure(ErrorCode::malformed, "ARM64 unwind names an invalid GPR");
                auto value = read64(memory, at); if (!value) return value.error();
                put_scalar(out, "x" + std::to_string(reg), value.value());
                if (reg == 29) put_scalar(out, "fp", value.value());
                if (reg == 30) put_scalar(out, "lr", value.value());
                return true;
            };
            auto restore_d = [&](std::uint8_t reg, std::uint64_t at) -> Result<bool> {
                if (reg > 31) return failure(ErrorCode::malformed, "ARM64 unwind names an invalid FP register");
                auto value = read_exact(memory, at, 8); if (!value) return value.error();
                out.registers["d" + std::to_string(reg)] = std::move(value.value());
                return true;
            };
            auto pair_x = [&](std::uint8_t reg, std::uint64_t at) -> Result<bool> {
                auto a = restore_x(reg, at); if (!a) return a.error();
                auto second = add(at, 8); if (!second) return second.error();
                return restore_x(static_cast<std::uint8_t>(reg + 1), second.value());
            };
            auto pair_d = [&](std::uint8_t reg, std::uint64_t at) -> Result<bool> {
                auto a = restore_d(reg, at); if (!a) return a.error();
                auto second = add(at, 8); if (!second) return second.error();
                return restore_d(static_cast<std::uint8_t>(reg + 1), second.value());
            };
            auto sve_length = [&]() -> Result<std::uint64_t> {
                auto length = scalar(out, "sve_vl"); if (!length) return length.error();
                if (length.value() < 16 || length.value() > 256 || (length.value() & 15u) != 0)
                    return failure(ErrorCode::invalid_argument, "ARM64 SVE vector length must be a supplied multiple of 16 bytes from 16 through 256");
                return length.value();
            };
            if (op <= 0x1f) { auto n = add(sp, static_cast<std::uint64_t>(op & 0x1f) * 16); if (!n) return n.error(); sp = n.value(); }
            else if (op <= 0x3f) {
                auto restored = pair_x(19, sp); if (!restored) return restored.error();
                previous_pair=PreviousPair::integer;previous_pair_register=19;previous_pair_address=sp;
                auto n = add(sp, static_cast<std::uint64_t>(op & 0x1f) * 8); if (!n) return n.error(); sp = n.value();
            } else if (op <= 0x7f) {
                auto a = add(sp, static_cast<std::uint64_t>(op & 0x3f) * 8); if (!a) return a.error();
                auto restored = pair_x(29, a.value()); if (!restored) return restored.error();
            } else if (op <= 0xbf) {
                auto restored = pair_x(29, sp); if (!restored) return restored.error();
                auto n = add(sp, (static_cast<std::uint64_t>(op & 0x3f) + 1) * 8); if (!n) return n.error(); sp = n.value();
            } else if (op <= 0xc7) {
                if (code.encoding.size()!=2) return failure(ErrorCode::malformed,"ARM64 alloc_m encoding has invalid size");
                auto n=add(sp,(((static_cast<std::uint64_t>(op&7)<<8)|code.encoding[1])*16));if(!n)return n.error();sp=n.value();
            } else if (op <= 0xcf) {
                if(code.encoding.size()!=2)return failure(ErrorCode::malformed,"ARM64 save_regp encoding has invalid size");
                const auto x=static_cast<std::uint8_t>(((op&3)<<2)|(code.encoding[1]>>6));
                const auto reg=static_cast<std::uint8_t>(19+2*x);const bool pre=(op&4)!=0;
                const auto z=code.encoding[1]&0x3f;auto at=pre?Result<std::uint64_t>(sp):add(sp,static_cast<std::uint64_t>(z)*8);if(!at)return at.error();
                auto restored=pair_x(reg,at.value());if(!restored)return restored.error();
                previous_pair=PreviousPair::integer;previous_pair_register=reg;previous_pair_address=at.value();
                if(pre){auto n=add(sp,(static_cast<std::uint64_t>(z)+1)*8);if(!n)return n.error();sp=n.value();}
            } else if (op <= 0xd3) {
                if(code.encoding.size()!=2)return failure(ErrorCode::malformed,"ARM64 save_reg encoding has invalid size");
                const auto reg=static_cast<std::uint8_t>(19+((op&3)<<2)+(code.encoding[1]>>6));
                auto at=add(sp,static_cast<std::uint64_t>(code.encoding[1]&0x3f)*8);if(!at)return at.error();auto restored=restore_x(reg,at.value());if(!restored)return restored.error();
            } else if (op <= 0xd5) {
                if(code.encoding.size()!=2)return failure(ErrorCode::malformed,"ARM64 save_reg_x encoding has invalid size");
                const auto reg=static_cast<std::uint8_t>(19+((op&1)<<3)+(code.encoding[1]>>5));auto restored=restore_x(reg,sp);if(!restored)return restored.error();
                auto n=add(sp,(static_cast<std::uint64_t>(code.encoding[1]&0x1f)+1)*8);if(!n)return n.error();sp=n.value();
            } else if (op <= 0xd7) {
                if(code.encoding.size()!=2)return failure(ErrorCode::malformed,"ARM64 save_lrpair encoding has invalid size");
                const auto reg=static_cast<std::uint8_t>(19+2*(((op&1)<<2)+(code.encoding[1]>>6)));
                auto at=add(sp,static_cast<std::uint64_t>(code.encoding[1]&0x3f)*8);if(!at)return at.error();auto restored=restore_x(reg,at.value());if(!restored)return restored.error();
                auto lr_at=add(at.value(),8);if(!lr_at)return lr_at.error();restored=restore_x(30,lr_at.value());if(!restored)return lr_at.error();
            } else if (op <= 0xdb) {
                if(code.encoding.size()!=2)return failure(ErrorCode::malformed,"ARM64 save_fregp encoding has invalid size");
                const auto reg=static_cast<std::uint8_t>(8+((op&1)<<2)+(code.encoding[1]>>6));const bool pre=(op&2)!=0;const auto z=code.encoding[1]&0x3f;
                auto at=pre?Result<std::uint64_t>(sp):add(sp,static_cast<std::uint64_t>(z)*8);if(!at)return at.error();auto restored=pair_d(reg,at.value());if(!restored)return restored.error();
                previous_pair=PreviousPair::floating;previous_pair_register=reg;previous_pair_address=at.value();
                if(pre){auto n=add(sp,(static_cast<std::uint64_t>(z)+1)*8);if(!n)return n.error();sp=n.value();}
            } else if (op <= 0xdd) {
                if(code.encoding.size()!=2)return failure(ErrorCode::malformed,"ARM64 save_freg encoding has invalid size");
                const auto reg=static_cast<std::uint8_t>(8+((op&1)<<2)+(code.encoding[1]>>6));auto at=add(sp,static_cast<std::uint64_t>(code.encoding[1]&0x3f)*8);if(!at)return at.error();auto restored=restore_d(reg,at.value());if(!restored)return restored.error();
            } else if (op == 0xde) {
                if(code.encoding.size()!=2)return failure(ErrorCode::malformed,"ARM64 save_freg_x encoding has invalid size");
                const auto reg=static_cast<std::uint8_t>(8+(code.encoding[1]>>5));auto restored=restore_d(reg,sp);if(!restored)return restored.error();auto n=add(sp,(static_cast<std::uint64_t>(code.encoding[1]&0x1f)+1)*8);if(!n)return n.error();sp=n.value();
            } else if (op == 0xdf) {
                if(code.encoding.size()!=2)return failure(ErrorCode::malformed,"ARM64 alloc_z encoding has invalid size");
                auto vl=sve_length();if(!vl)return vl.error();auto n=add(sp,static_cast<std::uint64_t>(code.encoding[1])*vl.value());if(!n)return n.error();sp=n.value();
            }
            else if (op == 0xe0) {
                if (code.encoding.size()!=4) return failure(ErrorCode::malformed,"ARM64 alloc_l encoding has invalid size");
                const std::uint64_t units=(static_cast<std::uint64_t>(code.encoding[1])<<16) | (static_cast<std::uint64_t>(code.encoding[2])<<8) | code.encoding[3];
                auto n=add(sp,units*16);if(!n)return n.error();sp=n.value();
            } else if (op == 0xe1) { auto fp=scalar(out,"fp");if(!fp)return fp.error();sp=fp.value(); }
            else if (op == 0xe2) { if(code.encoding.size()!=2)return failure(ErrorCode::malformed,"ARM64 add_fp encoding has invalid size");auto fp=scalar(out,"fp");if(!fp)return fp.error();const auto delta=static_cast<std::uint64_t>(code.encoding[1])*8;if(fp.value()<delta)return failure(ErrorCode::overflow,"ARM64 frame-pointer stack underflow");sp=fp.value()-delta; }
            else if (op == 0xe3 || op == 0xe5) { }
            else if (op == 0xe4) break;
            else if (op == 0xe6) {
                if(previous_pair==PreviousPair::none)return failure(ErrorCode::malformed,"ARM64 save_next has no preceding register pair");
                auto at=add(previous_pair_address,16);if(!at)return at.error();const auto reg=static_cast<std::uint8_t>(previous_pair_register+2);
                auto restored=previous_pair==PreviousPair::integer?pair_x(reg,at.value()):pair_d(reg,at.value());if(!restored)return restored.error();
                previous_pair_register=reg;previous_pair_address=at.value();
            } else if (op == 0xfc) return failure(ErrorCode::unsupported,"ARM64 pac_sign_lr requires target pointer-authentication keys");
            else if (op == 0xe7) {
                if(code.encoding.size()!=3)return failure(ErrorCode::malformed,"ARM64 save_any encoding has invalid size");
                const auto selector=code.encoding[1], extension=code.encoding[2];
                if(selector&0x80)return failure(ErrorCode::malformed,"ARM64 save_any selector uses a reserved high bit");
                const bool pair=(selector&0x40)!=0, pre=(selector&0x20)!=0;
                const auto kind=extension>>6; const auto reg=static_cast<std::uint8_t>(selector&0x1f);
                std::uint64_t offset=(extension&0x3f);
                if(kind==0 || kind==1 || kind==2) {
                    const auto maximum=static_cast<std::uint8_t>(kind==0?30:31);
                    if(reg>maximum || (pair && static_cast<unsigned>(reg)+1>maximum))return failure(ErrorCode::malformed,"ARM64 save_any register number exceeds its bank");
                    const auto width=kind==2?16u:8u;
                    const auto scale=kind==2||pre||pair?16u:8u;
                    const auto at=pre?Result<std::uint64_t>(sp):add(sp,offset*scale);if(!at)return at.error();
                    auto restore_any=[&](std::uint8_t n,std::uint64_t address)->Result<bool>{
                        const auto name=(kind==0?"x":kind==1?"d":"q")+std::to_string(n);
                        auto value=read_exact(memory,address,width);if(!value)return value.error();out.registers[name]=std::move(value.value());
                        if(kind==0&&(n==29||n==30)){auto scalar_value=scalar(out,name);if(!scalar_value)return scalar_value.error();put_scalar(out,n==29?"fp":"lr",scalar_value.value());}
                        return true;
                    };
                    auto restored=restore_any(reg,at.value());if(!restored)return restored.error();
                    if(pair){auto second=add(at.value(),width);if(!second)return second.error();restored=restore_any(static_cast<std::uint8_t>(reg+1),second.value());if(!restored)return restored.error();}
                    if(pair&&kind==0){previous_pair=PreviousPair::integer;previous_pair_register=reg;previous_pair_address=at.value();}
                    if(pair&&kind==1){previous_pair=PreviousPair::floating;previous_pair_register=reg;previous_pair_address=at.value();}
                    if(pre){auto n=add(sp,offset*scale);if(!n)return n.error();sp=n.value();}
                } else {
                    const auto high=(selector>>5)&3u; offset=(high<<6)|(extension&0x3f);
                    if((selector&0x10)==0) {
                        auto vl=sve_length();if(!vl)return vl.error();const auto zreg=static_cast<std::uint8_t>(8+(selector&0x0f));
                        if(zreg>23)return failure(ErrorCode::malformed,"ARM64 save_zreg number exceeds z23");
                        auto at=add(sp,offset*vl.value());if(!at)return at.error();auto value=read_exact(memory,at.value(),static_cast<std::size_t>(vl.value()));if(!value)return value.error();out.registers["z"+std::to_string(zreg)]=std::move(value.value());
                    } else if((selector&0x0f)==0) {
                        auto at=add(sp,offset*8);if(!at)return at.error();auto value=read64(memory,at.value());if(!value)return value.error();
                        if(value.value()&0x7fffffffffffffc0ull)return failure(ErrorCode::malformed,"ARM64 save_vg_sm value has nonzero reserved bits");
                        put_scalar(out,"sm",value.value()>>63);put_scalar(out,"vg",value.value()&0x3f);
                    } else {
                        const auto preg=selector&0x0f;
                        if(preg>=1&&preg<=3)return failure(ErrorCode::malformed,"ARM64 save_preg selector 1 through 3 is reserved");
                        auto vl=sve_length();if(!vl)return vl.error();const auto bytes=static_cast<std::size_t>(vl.value()/8);
                        auto at=add(sp,offset*bytes);if(!at)return at.error();auto value=read_exact(memory,at.value(),bytes);if(!value)return value.error();out.registers["p"+std::to_string(preg)]=std::move(value.value());
                    }
                }
            }
            else return failure(ErrorCode::unsupported,"ARM64 xdata opcode is unsupported by live unwinding");
        }
    } else return failure(ErrorCode::unsupported, "ARM64 pdata-link rows require resolving the linked record before live unwinding");
    put_scalar(out, "sp", sp);
    auto lr = scalar(out, "lr"); if (!lr) return lr.error();
    put_scalar(out, "pc", lr.value());
    return out;
}
} // namespace

Result<PeRegisterContext> unwind_pe_frame(const PeMetadata &metadata, Architecture architecture,
                                          std::uint64_t module_base, std::uint64_t instruction_pointer,
                                          const PeRegisterContext &context, const PeMemoryReader &memory) {
    if (architecture == Architecture::x86_64) return unwind_amd64(metadata, module_base, instruction_pointer, context, memory);
    if (architecture == Architecture::arm64) return unwind_arm64(metadata, module_base, instruction_pointer, context, memory);
    return failure(ErrorCode::unsupported, "PE live unwinding supports AMD64 and ARM64 only");
}

Result<PeFh3ExceptionPlan> plan_pe_fh3_exception(const PeMetadata &metadata, std::uint64_t module_base,
        std::uint64_t instruction_pointer, std::uint64_t establisher_frame,
        std::optional<std::string_view> exception_decorated_type) {
    if (instruction_pointer < module_base ||
        instruction_pointer - module_base > std::numeric_limits<std::uint32_t>::max())
        return failure(ErrorCode::out_of_bounds, "instruction pointer is outside the PE RVA range");
    const auto rva = static_cast<std::uint32_t>(instruction_pointer - module_base);
    constexpr std::size_t max_fh3_records = 1'000'000;
    constexpr std::size_t max_fh3_name_bytes = 1024 * 1024;
    if (metadata.exception_functions.size() > max_fh3_records)
        return failure(ErrorCode::resource_limit, "PE runtime-function count exceeds the FH3 planner budget");
    const PeRuntimeFunction *runtime = nullptr;
    bool multiple_owners = false;
    for (const auto &row : metadata.exception_functions) {
        if (row.begin_rva <= rva && rva < row.end_rva) {
            if (runtime) multiple_owners = true;
            else runtime = &row;
        }
    }
    if (multiple_owners) {
        PeFh3ExceptionPlan ambiguous;
        ambiguous.function_begin_rva = runtime->begin_rva;
        ambiguous.establisher_frame = establisher_frame;
        ambiguous.dispatch = PeFh3DispatchDisposition::ambiguous;
        ambiguous.dispatch_diagnostic = "multiple caller-supplied runtime functions own the live IP";
        return ambiguous;
    }
    if (!runtime || !runtime->unwind_info || !runtime->unwind_info->handler_payload ||
        !runtime->unwind_info->handler_payload->cxx_func_info)
        return failure(ErrorCode::unsupported, "no FH3 metadata is associated with the live runtime function");

    const auto &fh3 = *runtime->unwind_info->handler_payload->cxx_func_info;
    if (fh3.magic != 0x19930522u)
        return failure(ErrorCode::unsupported, "FH3 FuncInfo version is unsupported");
    if (fh3.unwind_map.size() > max_fh3_records || fh3.ip_to_state.size() > max_fh3_records ||
        fh3.try_blocks.size() > max_fh3_records)
        return failure(ErrorCode::resource_limit, "FH3 table exceeds the planner budget");
    if (fh3.max_state < 0 || static_cast<std::size_t>(fh3.max_state) != fh3.unwind_map.size())
        return failure(ErrorCode::malformed, "FH3 state or table extents are inconsistent");

    std::size_t total_handlers = 0;
    std::size_t total_name_bytes = 0;
    if (exception_decorated_type) {
        if (exception_decorated_type->size() > max_fh3_name_bytes)
            return failure(ErrorCode::resource_limit, "FH3 exception type name exceeds the planner byte budget");
        total_name_bytes = exception_decorated_type->size();
    }
    bool conflicting_duplicate_ip_state = false;
    for (std::size_t i = 0; i < fh3.ip_to_state.size(); ++i) {
        const auto &entry = fh3.ip_to_state[i];
        if (entry.ip_rva < runtime->begin_rva || entry.ip_rva > runtime->end_rva ||
            entry.state < -1 || entry.state >= fh3.max_state)
            return failure(ErrorCode::malformed, "FH3 IP-state row is outside its function or has an invalid state");
        if (i && fh3.ip_to_state[i - 1].ip_rva > entry.ip_rva)
            return failure(ErrorCode::malformed, "FH3 IP-state rows are unsorted");
        if (i && fh3.ip_to_state[i - 1].ip_rva == entry.ip_rva &&
            fh3.ip_to_state[i - 1].state != entry.state)
            conflicting_duplicate_ip_state = true;
    }
    for (std::size_t i = 0; i < fh3.unwind_map.size(); ++i) {
        const auto predecessor = fh3.unwind_map[i].to_state;
        if (predecessor < -1 || predecessor >= static_cast<std::int32_t>(i))
            return failure(ErrorCode::malformed, "FH3 unwind map has an invalid predecessor state");
    }
    for (const auto &try_block : fh3.try_blocks) {
        if (try_block.try_low < 0 || try_block.try_low > try_block.try_high ||
            try_block.try_high >= fh3.max_state || try_block.catch_high < try_block.try_high ||
            try_block.catch_high >= fh3.max_state)
            return failure(ErrorCode::malformed, "FH3 try-block state range is invalid");
        if (try_block.handlers.size() > max_fh3_records - total_handlers)
            return failure(ErrorCode::resource_limit, "FH3 handler count exceeds the planner budget");
        total_handlers += try_block.handlers.size();
        for (const auto &handler : try_block.handlers) {
            if (handler.decorated_type_name) {
                if (handler.decorated_type_name->size() > max_fh3_name_bytes - total_name_bytes)
                    return failure(ErrorCode::resource_limit, "FH3 decorated type names exceed the planner byte budget");
                total_name_bytes += handler.decorated_type_name->size();
            }
            if (handler.handler_rva == 0 || ((!handler.type_descriptor_rva || *handler.type_descriptor_rva == 0) && handler.decorated_type_name))
                return failure(ErrorCode::malformed, "FH3 handler or type-descriptor reference is invalid");
            if (handler.handler_rva > std::numeric_limits<std::uint64_t>::max() - module_base)
                return failure(ErrorCode::overflow, "FH3 handler address overflows");
            if (handler.type_descriptor_rva && *handler.type_descriptor_rva &&
                *handler.type_descriptor_rva > std::numeric_limits<std::uint64_t>::max() - module_base)
                return failure(ErrorCode::overflow, "FH3 type-descriptor address overflows");
        }
    }
    for (const auto &row : fh3.unwind_map)
        if (row.action_rva && row.action_rva > std::numeric_limits<std::uint64_t>::max() - module_base)
            return failure(ErrorCode::overflow, "FH3 cleanup action address overflows");

    PeFh3ExceptionPlan plan;
    plan.function_begin_rva = runtime->begin_rva;
    plan.establisher_frame = establisher_frame;
    plan.has_ehs_flag = fh3.has_ehs_flag;
    plan.has_dynamic_stack_alignment = fh3.has_dynamic_stack_alignment;
    plan.is_noexcept = fh3.is_noexcept;
    if (conflicting_duplicate_ip_state) {
        plan.dispatch = PeFh3DispatchDisposition::ambiguous;
        plan.dispatch_source = fh3.source;
        plan.dispatch_diagnostic = "duplicate FH3 IP transitions assign conflicting states";
        return plan;
    }
    const auto ip_entry = std::upper_bound(fh3.ip_to_state.begin(), fh3.ip_to_state.end(), rva,
        [](std::uint32_t address, const PeCxxIpToStateEntry &row) { return address < row.ip_rva; });
    if (ip_entry != fh3.ip_to_state.begin()) plan.state = std::prev(ip_entry)->state;
    if (plan.state < -1 || (plan.state >= 0 && plan.state >= fh3.max_state))
        return failure(ErrorCode::malformed, "FH3 live IP state exceeds the unwind map");

    if (plan.state >= 0) {
        auto current = plan.state;
        for (std::size_t depth = 0; current >= 0; ++depth) {
            if (depth >= max_unwind_operations)
                return failure(ErrorCode::resource_limit, "FH3 unwind action chain exceeds 512 entries");
            if (static_cast<std::size_t>(current) >= fh3.unwind_map.size())
                return failure(ErrorCode::malformed, "FH3 unwind action state exceeds the unwind map");
            const auto &row = fh3.unwind_map[static_cast<std::size_t>(current)];
            if (row.to_state < -1 || row.to_state >= current)
                return failure(ErrorCode::malformed, "FH3 unwind map has an invalid predecessor state");
            if (row.action_rva) {
                auto address = add(module_base, row.action_rva);
                if (!address) return address.error();
                plan.cleanup_actions.push_back({current, address.value(), row.source});
            }
            current = row.to_state;
        }
    }

    if (plan.state >= 0) {
        for (std::size_t try_index = 0; try_index < fh3.try_blocks.size(); ++try_index) {
            const auto &try_block = fh3.try_blocks[try_index];
            if (try_block.try_low < 0 || try_block.try_low > try_block.try_high ||
                try_block.try_high >= fh3.max_state || try_block.catch_high < try_block.try_high ||
                try_block.catch_high >= fh3.max_state)
                return failure(ErrorCode::malformed, "FH3 try-block state range is invalid");
            if (plan.state < try_block.try_low || plan.state > try_block.try_high) continue;
            for (std::size_t handler_index = 0; handler_index < try_block.handlers.size(); ++handler_index) {
                const auto &handler = try_block.handlers[handler_index];
                PeFh3CatchCandidate candidate;
                candidate.try_index = static_cast<std::uint32_t>(try_index);
                candidate.handler_index = static_cast<std::uint32_t>(handler_index);
                candidate.decorated_type_name = handler.decorated_type_name;
                candidate.source = handler.source;
                candidate.type_descriptor_source = handler.type_descriptor_source;
                auto handler_address = add(module_base, handler.handler_rva);
                if (!handler_address) return handler_address.error();
                candidate.handler_address = handler_address.value();
                const auto offset = static_cast<std::int64_t>(handler.catch_object_offset);
                if (offset >= 0) {
                    auto address = add(establisher_frame, static_cast<std::uint64_t>(offset));
                    if (!address) return address.error();
                    candidate.catch_object_address = address.value();
                } else {
                    const auto magnitude = static_cast<std::uint64_t>(-offset);
                    if (magnitude > establisher_frame)
                        return failure(ErrorCode::overflow, "FH3 catch-object address underflows the frame");
                    candidate.catch_object_address = establisher_frame - magnitude;
                }

                if (handler.adjectives != 0)
                    candidate.disposition = PeFh3CatchDisposition::unsupported_adjectives;
                else if (!handler.type_descriptor_rva || *handler.type_descriptor_rva == 0)
                    candidate.disposition = PeFh3CatchDisposition::catch_all;
                else if (!exception_decorated_type)
                    candidate.disposition = PeFh3CatchDisposition::type_unknown;
                else if (handler.decorated_type_name &&
                         *handler.decorated_type_name == *exception_decorated_type)
                    candidate.disposition = PeFh3CatchDisposition::exact_type;
                else if (handler.decorated_type_name)
                    candidate.disposition = PeFh3CatchDisposition::different_type;
                else
                    candidate.disposition = PeFh3CatchDisposition::type_unknown;
                plan.handlers.push_back(std::move(candidate));
            }
        }
    }

    bool uncertain_match = false;
    std::size_t provable_match_count = 0;
    for (const auto &candidate : plan.handlers) {
        switch (candidate.disposition) {
        case PeFh3CatchDisposition::different_type:
            break;
        case PeFh3CatchDisposition::type_unknown:
        case PeFh3CatchDisposition::unsupported_adjectives:
            uncertain_match = true;
            break;
        case PeFh3CatchDisposition::catch_all:
        case PeFh3CatchDisposition::exact_type:
            ++provable_match_count;
            if (uncertain_match) {
                plan.dispatch = PeFh3DispatchDisposition::ambiguous;
                plan.dispatch_source = candidate.source;
                plan.dispatch_diagnostic = "an earlier FH3 catch with unmodeled matching semantics prevents handler selection";
                return plan;
            }
            break;
        }
    }
    if (provable_match_count == 1 && !uncertain_match) {
        for (const auto &candidate : plan.handlers) {
            if (candidate.disposition == PeFh3CatchDisposition::catch_all ||
                candidate.disposition == PeFh3CatchDisposition::exact_type) {
                plan.dispatch = PeFh3DispatchDisposition::handler_candidate;
                plan.selected_try_index = candidate.try_index;
                plan.selected_handler_index = candidate.handler_index;
                plan.dispatch_source = candidate.source;
                plan.dispatch_diagnostic = "only provable matching FH3 handler candidate";
                return plan;
            }
        }
    }
    if (provable_match_count > 1) {
        plan.dispatch = PeFh3DispatchDisposition::ambiguous;
        plan.dispatch_source = fh3.source;
        plan.dispatch_diagnostic = "multiple provable FH3 catches cannot be ordered from caller-supplied try-block rows";
        return plan;
    }
    if (uncertain_match) {
        plan.dispatch = PeFh3DispatchDisposition::ambiguous;
        plan.dispatch_source = fh3.source;
        plan.dispatch_diagnostic = "FH3 catch matching requires a decorated exception type and supported handler adjectives";
    } else if (fh3.exception_spec_types) {
        const auto &specification = *fh3.exception_spec_types;
        if (fh3.is_noexcept) {
            plan.dispatch = PeFh3DispatchDisposition::ambiguous;
            plan.dispatch_source = fh3.eh_flags_source ? fh3.eh_flags_source
                                                       : std::optional<PeRecordSource>{fh3.source};
            plan.dispatch_diagnostic = "FH3 FuncInfo combines noexcept and a dynamic exception type list";
        } else if (specification.types.empty()) {
            plan.exception_spec_allows = false;
            plan.dispatch = PeFh3DispatchDisposition::unexpected_exception_spec;
            plan.dispatch_source = specification.source;
            plan.dispatch_diagnostic = "the empty FH3 exception specification allows no C++ exception type";
        } else if (!exception_decorated_type) {
            plan.dispatch = PeFh3DispatchDisposition::ambiguous;
            plan.dispatch_source = specification.source;
            plan.dispatch_diagnostic = "FH3 exception-specification matching requires an exact decorated exception type";
        } else {
            bool unresolved_type = false;
            for (std::size_t type_index = 0; type_index < specification.types.size(); ++type_index) {
                const auto &allowed = specification.types[type_index];
                if (allowed.adjectives != 0 || !allowed.type_descriptor_rva ||
                    *allowed.type_descriptor_rva == 0 || !allowed.decorated_type_name) {
                    unresolved_type = true;
                    continue;
                }
                if (*allowed.decorated_type_name == *exception_decorated_type) {
                    plan.exception_spec_allows = true;
                    plan.exception_spec_type_index = static_cast<std::uint32_t>(type_index);
                    plan.dispatch = PeFh3DispatchDisposition::continue_search;
                    plan.dispatch_source = allowed.source;
                    plan.dispatch_diagnostic = "exact decorated type is permitted by the FH3 dynamic exception specification";
                    return plan;
                }
            }
            if (unresolved_type) {
                plan.dispatch = PeFh3DispatchDisposition::ambiguous;
                plan.dispatch_source = specification.source;
                plan.dispatch_diagnostic = "an unresolved or qualified FH3 exception-specification type prevents safe classification";
            } else {
                plan.exception_spec_allows = false;
                plan.dispatch = PeFh3DispatchDisposition::unexpected_exception_spec;
                plan.dispatch_source = specification.source;
                plan.dispatch_diagnostic = "the exact decorated exception type is not listed by the FH3 dynamic exception specification";
            }
        }
    } else if (fh3.is_noexcept) {
        plan.dispatch = PeFh3DispatchDisposition::terminate_noexcept;
        plan.dispatch_source = fh3.eh_flags_source ? fh3.eh_flags_source
                                                   : std::optional<PeRecordSource>{fh3.source};
        plan.dispatch_diagnostic = "C++ exception has no provable active handler in an FH3 noexcept function";
    } else {
        plan.dispatch = PeFh3DispatchDisposition::continue_search;
        plan.dispatch_source = fh3.source;
        plan.dispatch_diagnostic = "no provable active FH3 handler; continue searching outer frames";
    }
    return plan;
}

Result<PeFh4ExceptionPlan> plan_pe_fh4_exception(const PeMetadata &metadata, std::uint64_t module_base,
        std::uint64_t instruction_pointer, std::uint64_t establisher_frame,
        std::optional<std::string_view> exception_decorated_type, const PeMemoryReader &memory,
        PeFh4ExceptionKind exception_kind) {
    if (metadata.exception_functions.size() > max_fh4_metadata_records)
        return failure(ErrorCode::resource_limit, "FH4 runtime-function table exceeds one million rows");
    if (instruction_pointer < module_base ||
        instruction_pointer - module_base > std::numeric_limits<std::uint32_t>::max())
        return failure(ErrorCode::out_of_bounds, "instruction pointer is outside the PE RVA range");
    const auto rva=static_cast<std::uint32_t>(instruction_pointer-module_base);
    const PeRuntimeFunction *runtime=nullptr;
    for(const auto& row:metadata.exception_functions) {
        if (row.begin_rva >= row.end_rva)
            return failure(ErrorCode::malformed, "PE runtime-function extent is empty");
        if(row.begin_rva<=rva&&rva<row.end_rva) {
            if (runtime) return failure(ErrorCode::invalid_argument, "overlapping PE runtime-function rows make FH4 ownership ambiguous");
            runtime=&row;
        }
    }
    if(!runtime||!runtime->unwind_info||!runtime->unwind_info->handler_payload||
       !runtime->unwind_info->handler_payload->cxx_func_info4)
        return failure(ErrorCode::unsupported,"no FH4 metadata is associated with the live runtime function");
    const auto& fh4=*runtime->unwind_info->handler_payload->cxx_func_info4;
    if(fh4.status==PeCxxFuncInfo4Status::malformed)
        return failure(ErrorCode::malformed,"FH4 metadata is malformed: "+fh4.diagnostic);
    if(fh4.status!=PeCxxFuncInfo4Status::decoded_subset)
        return failure(ErrorCode::unsupported,"FH4 metadata is unsupported: "+fh4.diagnostic);

    // PeMetadata is a public value model and callers can construct it without
    // passing through the loader's parser budgets. Reapply those limits before
    // traversing or copying any FH4 vectors into the returned plan.
    if (fh4.unwind_map.size() > max_fh4_metadata_records ||
        fh4.ip_to_state.size() > max_fh4_metadata_records ||
        fh4.try_blocks.size() > max_fh4_metadata_records)
        return failure(ErrorCode::resource_limit, "FH4 state tables exceed one million rows");
    if (exception_decorated_type && exception_decorated_type->size() > max_fh4_name_bytes)
        return failure(ErrorCode::resource_limit, "FH4 exception type name exceeds the one MiB comparison budget");
    std::size_t aggregate_records = fh4.unwind_map.size() + fh4.ip_to_state.size() + fh4.try_blocks.size();
    if (aggregate_records > max_fh4_metadata_records)
        return failure(ErrorCode::resource_limit, "FH4 aggregate state tables exceed one million rows");
    std::size_t aggregate_name_bytes = exception_decorated_type ? exception_decorated_type->size() : 0;
    for (std::size_t i = 0; i < fh4.unwind_map.size(); ++i) {
        const auto &entry = fh4.unwind_map[i];
        if (entry.previous_entry_index && *entry.previous_entry_index >= i)
            return failure(ErrorCode::malformed, "FH4 unwind link is not a backward link");
        if (entry.type != PeCxxUnwindEntry4Type::no_action && !entry.action_rva)
            return failure(ErrorCode::malformed, "FH4 cleanup entry has no action RVA");
        if ((entry.type == PeCxxUnwindEntry4Type::destructor_object ||
             entry.type == PeCxxUnwindEntry4Type::destructor_pointer) && !entry.object_offset)
            return failure(ErrorCode::malformed, "FH4 destructor entry has no object offset");
        if (static_cast<unsigned>(entry.type) > static_cast<unsigned>(PeCxxUnwindEntry4Type::action_rva))
            return failure(ErrorCode::malformed, "FH4 unwind entry type is reserved");
    }
    std::uint32_t previous_ip = 0;
    bool first_ip = true;
    for (const auto &entry : fh4.ip_to_state) {
        if (entry.ip_rva < runtime->begin_rva || entry.ip_rva >= runtime->end_rva ||
            (!first_ip && entry.ip_rva < previous_ip))
            return failure(ErrorCode::malformed, "FH4 IP-to-state rows are unordered or outside their function");
        if (entry.state < -1 || (entry.state >= 0 && static_cast<std::size_t>(entry.state) >= fh4.unwind_map.size()))
            return failure(ErrorCode::malformed, "FH4 IP-to-state row exceeds the unwind map");
        previous_ip = entry.ip_rva;
        first_ip = false;
    }
    for (const auto &try_block : fh4.try_blocks) {
        if (try_block.try_low < -1 || try_block.try_high < -1 || try_block.catch_high < -1 ||
            try_block.try_low > try_block.try_high || try_block.catch_high < try_block.try_high ||
            (try_block.try_low >= 0 && static_cast<std::size_t>(try_block.try_low) >= fh4.unwind_map.size()) ||
            (try_block.try_high >= 0 && static_cast<std::size_t>(try_block.try_high) >= fh4.unwind_map.size()) ||
            (try_block.catch_high >= 0 && static_cast<std::size_t>(try_block.catch_high) >= fh4.unwind_map.size()))
            return failure(ErrorCode::malformed, "FH4 try-state range exceeds the unwind map");
        if (try_block.handlers.size() > max_fh4_metadata_records - aggregate_records)
            return failure(ErrorCode::resource_limit, "FH4 handler records exceed one million rows");
        aggregate_records += try_block.handlers.size();
        for (const auto &handler : try_block.handlers) {
            if (handler.continuation_addresses.size() > max_fh4_metadata_records - aggregate_records)
                return failure(ErrorCode::resource_limit, "FH4 continuation records exceed one million rows");
            aggregate_records += handler.continuation_addresses.size();
            if (handler.decorated_type_name) {
                if (handler.decorated_type_name->size() > max_fh4_name_bytes - aggregate_name_bytes)
                    return failure(ErrorCode::resource_limit, "FH4 catch type names exceed the one MiB comparison budget");
                aggregate_name_bytes += handler.decorated_type_name->size();
            }
            for (const auto continuation : handler.continuation_addresses) {
                if (!handler.continuation_addresses_are_rvas &&
                    continuation >= runtime->end_rva - runtime->begin_rva)
                    return failure(ErrorCode::malformed, "FH4 continuation address exceeds its encoded extent");
            }
        }
    }

    PeFh4ExceptionPlan plan;
    plan.function_begin_rva=runtime->begin_rva;
    plan.is_catch_funclet=fh4.is_catch_funclet;
    plan.has_ehs_flag=fh4.has_ehs_flag;
    plan.is_noexcept=fh4.is_noexcept;
    plan.function_frame=establisher_frame;
    if(fh4.is_catch_funclet){
        if(!fh4.catch_frame)return failure(ErrorCode::malformed,"FH4 catch funclet has no frame displacement");
        auto frame=add(establisher_frame,*fh4.catch_frame);if(!frame)return frame.error();
        plan.function_frame=frame.value();
    }

    const auto state_entry=std::upper_bound(fh4.ip_to_state.begin(),fh4.ip_to_state.end(),rva,
        [](std::uint32_t address,const PeCxxIpToState4Entry& row){return address<row.ip_rva;});
    if(state_entry!=fh4.ip_to_state.begin())plan.state=std::prev(state_entry)->state;
    if(plan.state>=0){
        if(static_cast<std::size_t>(plan.state)>=fh4.unwind_map.size())
            return failure(ErrorCode::malformed,"FH4 live IP state exceeds the unwind map");
        auto current=plan.state;
        for(std::size_t depth=0;current>=0;++depth){
            if(depth>=max_unwind_operations)
                return failure(ErrorCode::resource_limit,"FH4 unwind action chain exceeds 512 entries");
            if(static_cast<std::size_t>(current)>=fh4.unwind_map.size())
                return failure(ErrorCode::malformed,"FH4 unwind action link exceeds the unwind map");
            const auto& row=fh4.unwind_map[static_cast<std::size_t>(current)];
            if(row.type!=PeCxxUnwindEntry4Type::no_action){
                if(!row.action_rva)return failure(ErrorCode::malformed,"FH4 cleanup action has no action RVA");
                auto action=add(module_base,*row.action_rva);if(!action)return action.error();
                PeFh4CleanupAction result;result.state=current;result.kind=row.type;
                result.action_address=action.value();result.source=row.source;
                result.action_source=row.action_source;result.object_source=row.object_source;
                if(row.type==PeCxxUnwindEntry4Type::destructor_object||
                   row.type==PeCxxUnwindEntry4Type::destructor_pointer){
                    if(!row.object_offset)return failure(ErrorCode::malformed,"FH4 destructor action has no object offset");
                    auto slot=add(plan.function_frame,*row.object_offset);if(!slot)return slot.error();
                    result.object_slot_address=slot.value();
                    if(row.type==PeCxxUnwindEntry4Type::destructor_object)result.object_address=slot.value();
                    else {
                        auto object=read64(memory,slot.value());if(!object)return object.error();
                        result.object_address=object.value();result.null_object_pointer=object.value()==0;
                    }
                }
                plan.cleanup_actions.push_back(std::move(result));
            }
            current=row.previous_entry_index?static_cast<std::int32_t>(*row.previous_entry_index):-1;
        }
    }
    const auto effective_kind = exception_decorated_type
        ? PeFh4ExceptionKind::cxx : exception_kind;
    if(plan.state>=0){
        for(std::size_t try_index=0;try_index<fh4.try_blocks.size();++try_index){
            const auto& try_block=fh4.try_blocks[try_index];
            if(plan.state<try_block.try_low||plan.state>try_block.try_high)continue;
            for(std::size_t handler_index=0;handler_index<try_block.handlers.size();++handler_index){
                const auto& handler=try_block.handlers[handler_index];
                PeFh4CatchCandidate candidate;
                candidate.try_index=static_cast<std::uint32_t>(try_index);
                candidate.handler_index=static_cast<std::uint32_t>(handler_index);
                candidate.decorated_type_name=handler.decorated_type_name;
                candidate.source=handler.source;
                auto target=add(module_base,handler.handler_rva);if(!target)return target.error();
                candidate.handler_address=target.value();
                if(handler.catch_object_offset){
                    auto object=add(plan.function_frame,*handler.catch_object_offset);if(!object)return object.error();
                    candidate.catch_object_address=object.value();
                }
                for(const auto continuation:handler.continuation_addresses){
                    Result<std::uint64_t> address=handler.continuation_addresses_are_rvas
                        ? add(module_base,continuation)
                        : add(module_base,std::uint64_t{runtime->begin_rva}+continuation);
                    if(!address)return address.error();
                    candidate.continuation_addresses.push_back(address.value());
                }
                const bool catch_all=!handler.type_descriptor_rva||*handler.type_descriptor_rva==0;
                const auto adjectives=handler.adjectives.value_or(0);
                if(catch_all)candidate.disposition=adjectives==0
                    ? PeFh4CatchDisposition::catch_all:PeFh4CatchDisposition::unsupported_adjectives;
                else if(adjectives!=0)candidate.disposition=PeFh4CatchDisposition::unsupported_adjectives;
                else if(!exception_decorated_type)candidate.disposition=PeFh4CatchDisposition::type_unknown;
                else if(handler.decorated_type_name&&*handler.decorated_type_name==*exception_decorated_type)
                    candidate.disposition=PeFh4CatchDisposition::exact_type;
                else candidate.disposition=PeFh4CatchDisposition::different_type;
                plan.handlers.push_back(std::move(candidate));
            }
        }
    }
    if (effective_kind == PeFh4ExceptionKind::non_cxx && fh4.has_ehs_flag) {
        plan.dispatch = PeFh4DispatchDisposition::continue_search;
        plan.dispatch_source = fh4.source;
        plan.dispatch_diagnostic = "FH4 EHs metadata handles C++ exceptions only";
        return plan;
    }
    bool uncertain_match = false;
    for (const auto &candidate : plan.handlers) {
        switch (candidate.disposition) {
        case PeFh4CatchDisposition::different_type:
            break;
        case PeFh4CatchDisposition::type_unknown:
            if (effective_kind != PeFh4ExceptionKind::non_cxx) uncertain_match = true;
            break;
        case PeFh4CatchDisposition::unsupported_adjectives:
            uncertain_match = true;
            break;
        case PeFh4CatchDisposition::catch_all:
            if (uncertain_match ||
                (effective_kind == PeFh4ExceptionKind::unknown && fh4.has_ehs_flag)) {
                plan.dispatch = PeFh4DispatchDisposition::ambiguous;
                plan.dispatch_source = candidate.source;
                plan.dispatch_diagnostic = "an earlier or unknown catch match prevents safe handler selection";
                return plan;
            }
            plan.dispatch = PeFh4DispatchDisposition::handler_candidate;
            plan.selected_try_index = candidate.try_index;
            plan.selected_handler_index = candidate.handler_index;
            plan.dispatch_source = candidate.source;
            plan.dispatch_diagnostic = "first provable matching FH4 handler candidate in metadata order";
            return plan;
        case PeFh4CatchDisposition::exact_type:
            if (uncertain_match) {
                plan.dispatch = PeFh4DispatchDisposition::ambiguous;
                plan.dispatch_source = candidate.source;
                plan.dispatch_diagnostic = "an earlier catch with unsupported matching semantics prevents safe handler selection";
                return plan;
            }
            plan.dispatch = PeFh4DispatchDisposition::handler_candidate;
            plan.selected_try_index = candidate.try_index;
            plan.selected_handler_index = candidate.handler_index;
            plan.dispatch_source = candidate.source;
            plan.dispatch_diagnostic = "first provable matching FH4 handler candidate in metadata order";
            return plan;
        }
    }
    if (uncertain_match || effective_kind == PeFh4ExceptionKind::unknown) {
        plan.dispatch = PeFh4DispatchDisposition::ambiguous;
        plan.dispatch_source = fh4.source;
        plan.dispatch_diagnostic = "FH4 catch matching requires exception kind/type or unsupported type semantics";
    } else if (effective_kind == PeFh4ExceptionKind::cxx && fh4.is_noexcept && !fh4.is_catch_funclet) {
        plan.dispatch = PeFh4DispatchDisposition::terminate_noexcept;
        plan.dispatch_diagnostic = "C++ exception has no provable active handler in a noexcept function";
        plan.dispatch_source = fh4.source;
    } else {
        plan.dispatch = PeFh4DispatchDisposition::continue_search;
        plan.dispatch_source = fh4.source;
        plan.dispatch_diagnostic = "no provable active FH4 handler; continue searching outer frames";
    }
    return plan;
}

} // namespace hexlab
