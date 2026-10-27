#include "elf_internal.hpp"

#include <algorithm>
#include <iterator>
#include <string_view>

namespace hexlab::elf_detail {
namespace {
constexpr std::uint16_t et_core = 4;
constexpr std::uint32_t nt_prstatus = 1;
constexpr std::uint32_t nt_prpsinfo = 3;
constexpr std::uint32_t nt_auxv = 6;
constexpr std::uint32_t nt_siginfo = 0x53494749;
constexpr std::uint32_t nt_file = 0x46494c45;
constexpr std::uint64_t core_record_limit = 1'000'000;
constexpr std::size_t elf64_prstatus_register_offset = 112;
constexpr std::size_t elf32_prstatus_register_offset = 72;

std::uint64_t note_value(std::span<const std::byte> bytes, std::size_t offset,
                         std::size_t width, ByteOrder order) {
    require(offset <= bytes.size() && width <= bytes.size() - offset,
            "ELF core note field is truncated");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i) {
        const auto shift_index = order == ByteOrder::little ? i : width - i - 1;
        value |= std::to_integer<std::uint64_t>(bytes[offset + i]) << (shift_index * 8);
    }
    return value;
}

std::string fixed_string(std::span<const std::byte> bytes) {
    const auto end = std::find(bytes.begin(), bytes.end(), std::byte{0});
    return {reinterpret_cast<const char *>(bytes.data()),
            static_cast<std::size_t>(end - bytes.begin())};
}

bool linux_core_note(const ElfNote &note) {
    return note.name == "CORE" || note.name == "LINUX";
}

void diagnostic(ElfCoreInfo &core, Budget &budget, std::string text) {
    budget.include(sizeof(std::string) + text.size());
    core.diagnostics.push_back(std::move(text));
}

void read_process_info(const ElfHeader &header, const ElfNote &note,
                       ElfCoreInfo &core, Budget &budget) {
    const auto bytes = std::span<const std::byte>(note.description);
    if (!header.is_64) {
        diagnostic(core, budget, "ELF32 NT_PRPSINFO process fields are retained only as a generic note");
        return;
    }
    // Linux's ELF64 elf_prpsinfo layout: four state bytes, aligned unsigned
    // long flags, 32-bit uid/gid and IDs, then fixed command-name/argument arrays.
    constexpr std::size_t process_info_size = 136;
    if (bytes.size() < process_info_size) {
        diagnostic(core, budget, "ELF64 NT_PRPSINFO note is shorter than its fixed Linux record");
        return;
    }
    const auto id = [&](std::size_t at) {
        return static_cast<std::uint32_t>(note_value(bytes, at, 4, header.order));
    };
    core.process_id = id(24);
    core.parent_process_id = id(28);
    core.process_group_id = id(32);
    core.session_id = id(36);
    core.executable = fixed_string(bytes.subspan(40, 16));
    core.arguments = fixed_string(bytes.subspan(56, 80));
    budget.include(sizeof(std::uint32_t) * 4 + core.executable->size() + core.arguments->size());
}

void read_thread_status(const ElfHeader &header, const ElfNote &note,
                        ElfCoreInfo &core, Budget &budget) {
    ElfCoreThread thread;
    thread.note_file_offset = note.file_offset;
    thread.payload_file_offset = note.description_file_offset;
    thread.register_byte_order = header.order;
    thread.status = ElfCoreThreadStatus::unsupported;
    const auto bytes = std::span<const std::byte>(note.description);
    const auto decode_registers = [&](std::vector<std::string> names, std::size_t offset,
                                      std::size_t word, std::string_view layout) {
        const auto register_bytes = names.size() * word;
        if (offset > bytes.size() || register_bytes > bytes.size() - offset) {
            thread.status = ElfCoreThreadStatus::malformed;
            thread.diagnostic = "NT_PRSTATUS register set is truncated for its machine";
            return;
        }
        if (note.description_file_offset > UINT64_MAX - offset ||
            register_bytes > UINT64_MAX - note.description_file_offset - offset) {
            thread.status = ElfCoreThreadStatus::malformed;
            thread.diagnostic = "NT_PRSTATUS register source offsets overflow";
            return;
        }
        const auto named = std::count_if(names.begin(), names.end(), [](const auto &name) { return !name.empty(); });
        budget.include(static_cast<std::uint64_t>(named) * sizeof(ElfCoreRegister) + layout.size());
        for (const auto &name : names) budget.include(name.size());
        thread.registers.reserve(static_cast<std::size_t>(named));
        thread.register_layout = layout;
        thread.gregset_file_offset = note.description_file_offset + offset;
        thread.gregset_slots = static_cast<std::uint16_t>(names.size());
        thread.register_word_bits = static_cast<std::uint16_t>(word * 8);
        for (std::size_t i = 0; i < names.size(); ++i) {
            if (names[i].empty()) continue;
            thread.registers.push_back({std::move(names[i]), note_value(bytes, offset + i * word, word, header.order),
                static_cast<std::uint16_t>(word * 8), static_cast<std::uint16_t>(i),
                note.description_file_offset + offset + i * word,
                layout == "linux-mips-o32" && (i == 32 || i == 33)});
        }
        thread.status = ElfCoreThreadStatus::decoded;
    };
    if ((header.os_abi != 0 && header.os_abi != 3) || header.abi_version != 0) {
        thread.diagnostic = "NT_PRSTATUS Linux register ABI is unsupported for this ELF OSABI/version";
    } else if (header.is_64) {
        // elf_prstatus_common is 112 bytes in the ELF64 Linux ABI: the
        // siginfo/current-signal fields, two 64-bit masks, four 32-bit IDs,
        // and four 64-bit timevals. General registers follow this prefix.
        if (bytes.size() < elf64_prstatus_register_offset) {
            thread.status = ElfCoreThreadStatus::malformed;
            thread.diagnostic = "ELF64 NT_PRSTATUS note is shorter than elf_prstatus_common";
        } else {
            thread.current_signal = static_cast<std::int16_t>(note_value(bytes, 12, 2, header.order));
            thread.process_id = static_cast<std::uint32_t>(note_value(bytes, 32, 4, header.order));
            thread.parent_process_id = static_cast<std::uint32_t>(note_value(bytes, 36, 4, header.order));
            thread.process_group_id = static_cast<std::uint32_t>(note_value(bytes, 40, 4, header.order));
            thread.session_id = static_cast<std::uint32_t>(note_value(bytes, 44, 4, header.order));
            std::vector<std::string> names;
            if (header.machine == 62 && header.order == ByteOrder::little) {
                names = {"r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
                         "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp",
                         "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"};
            } else if (header.machine == 183 && header.order == ByteOrder::little) {
                names.reserve(34);
                for (unsigned i = 0; i < 31; ++i)
                    names.push_back("x" + std::to_string(i));
                names.emplace_back("sp");
                names.emplace_back("pc");
                names.emplace_back("pstate");
            } else if (header.machine == 243 && header.order == ByteOrder::little &&
                       (header.flags & 8u) == 0) {
                names = {"pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1",
                         "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
                         "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"};
            }
            if (names.empty()) {
                thread.diagnostic = "NT_PRSTATUS register decoding supports little-endian x86-64, AArch64 "
                                    "and RISC-V64 only";
            } else {
                decode_registers(std::move(names), elf64_prstatus_register_offset, 8,
                    header.machine == 62 ? "linux-x86_64" : header.machine == 183 ? "linux-aarch64" :
                    "linux-riscv64");
            }
        }
    } else {
        if (bytes.size() < elf32_prstatus_register_offset) {
            thread.status = ElfCoreThreadStatus::malformed;
            thread.diagnostic = "ELF32 NT_PRSTATUS note is shorter than elf_prstatus_common";
        } else {
            thread.current_signal = static_cast<std::int16_t>(note_value(bytes, 12, 2, header.order));
            // Two 32-bit signal masks occupy offsets 16 and 20. IDs follow;
            // four old 32-bit timevals complete the 72-byte common prefix.
            thread.process_id = static_cast<std::uint32_t>(note_value(bytes, 24, 4, header.order));
            thread.parent_process_id = static_cast<std::uint32_t>(note_value(bytes, 28, 4, header.order));
            thread.process_group_id = static_cast<std::uint32_t>(note_value(bytes, 32, 4, header.order));
            thread.session_id = static_cast<std::uint32_t>(note_value(bytes, 36, 4, header.order));
            std::vector<std::string> names;
            std::string_view layout;
            if (header.machine == 3 && header.order == ByteOrder::little) {
                names = {"ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "ds", "es", "fs", "gs",
                         "orig_eax", "eip", "cs", "eflags", "esp", "ss"};
                layout = "linux-i386";
            } else if (header.machine == 40 &&
                       ((header.flags & 0xff000000u) == 0 || (header.flags & 0xff000000u) == 0x04000000u ||
                        (header.flags & 0xff000000u) == 0x05000000u) &&
                       !((header.flags & 0xff000000u) == 0 && (header.flags & 8u))) {
                for (unsigned i = 0; i < 13; ++i) names.push_back("r" + std::to_string(i));
                names.insert(names.end(), {"sp", "lr", "pc", "cpsr", "orig_r0"});
                layout = "linux-arm32";
            } else if (header.machine == 8 && (header.flags & 0x20u) == 0 &&
                       ((header.flags & 0xf000u) == 0 || (header.flags & 0xf000u) == 0x1000u)) {
                // O32 retains six prefix slots and one trailing unused slot.
                // They are not architectural registers and are not invented as
                // named values. Keep the exact indices of the 38 named slots.
                names.resize(45);
                for (unsigned i = 0; i < 32; ++i) names[6 + i] = "r" + std::to_string(i);
                names[38] = "lo"; names[39] = "hi"; names[40] = "pc";
                names[41] = "badvaddr"; names[42] = "status"; names[43] = "cause";
                layout = "linux-mips-o32";
            } else if (header.machine == 243 && header.order == ByteOrder::little && (header.flags & 8u) == 0) {
                names = {"pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3",
                         "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
                         "t3", "t4", "t5", "t6"};
                layout = "linux-riscv32";
            }
            if (names.empty()) {
                thread.diagnostic = "ELF32 NT_PRSTATUS machine, byte order or register ABI is unsupported";
            } else {
                const auto record_size = elf32_prstatus_register_offset + names.size() * 4 + 4;
                if (bytes.size() < record_size) {
                    thread.status = ElfCoreThreadStatus::malformed;
                    thread.diagnostic = "ELF32 NT_PRSTATUS gregset or trailing pr_fpvalid is truncated";
                } else if (bytes.size() != record_size) {
                    thread.diagnostic = "ELF32 NT_PRSTATUS size does not match the supported Linux register ABI";
                } else {
                    const auto fp_at = record_size - 4;
                    decode_registers(std::move(names), elf32_prstatus_register_offset, 4, layout);
                    if (thread.status == ElfCoreThreadStatus::decoded)
                        thread.floating_point_valid = static_cast<std::uint32_t>(note_value(bytes, fp_at, 4, header.order));
                }
            }
        }
    }
    budget.include(sizeof(ElfCoreThread) + thread.diagnostic.size());
    core.threads.push_back(std::move(thread));
}

void read_auxiliary_values(const ElfHeader &header, const ElfNote &note,
                           ElfCoreInfo &core, Budget &budget, std::stop_token stop) {
    const auto bytes = std::span<const std::byte>(note.description);
    const std::size_t word = header.is_64 ? 8 : 4;
    require(bytes.size() % (word * 2) == 0, "ELF NT_AUXV payload is not a whole number of type/value pairs");
    std::vector<ElfCoreAuxiliaryValue> rows;
    bool terminated = false;
    for (std::size_t at = 0; at < bytes.size(); at += word * 2) {
        canceled(stop);
        const auto type = note_value(bytes, at, word, header.order);
        const auto value = note_value(bytes, at + word, word, header.order);
        if (type == 0) { terminated = true; break; }
        require(rows.size() < core_record_limit, "ELF NT_AUXV exceeds record budget", ErrorCode::resource_limit);
        rows.push_back({type, value, note.file_offset, note.description_file_offset + at});
    }
    require(terminated, "ELF NT_AUXV has no AT_NULL terminator");
    budget.include(rows.size() * sizeof(ElfCoreAuxiliaryValue));
    core.auxiliary_values.insert(core.auxiliary_values.end(), rows.begin(), rows.end());
}

void read_file_mappings(const ElfHeader &header, const ElfNote &note,
                        ElfCoreInfo &core, Budget &budget, std::stop_token stop) {
    const auto bytes = std::span<const std::byte>(note.description);
    const std::size_t word = header.is_64 ? 8 : 4;
    require(bytes.size() >= word * 2, "ELF NT_FILE payload is shorter than its header");
    const auto count = note_value(bytes, 0, word, header.order);
    const auto page_size = note_value(bytes, word, word, header.order);
    require(page_size != 0, "ELF NT_FILE page size is zero");
    require(count <= core_record_limit, "ELF NT_FILE mapping count exceeds record budget", ErrorCode::resource_limit);
    require(count <= (bytes.size() - word * 2) / (word * 3), "ELF NT_FILE mapping table is truncated");
    const auto path_offset = word * 2 + static_cast<std::size_t>(count) * word * 3;
    std::size_t path_cursor = path_offset;
    std::vector<ElfCoreFileMapping> rows;
    rows.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        canceled(stop);
        const auto at = word * 2 + static_cast<std::size_t>(i) * word * 3;
        const auto start = note_value(bytes, at, word, header.order);
        const auto end = note_value(bytes, at + word, word, header.order);
        const auto page_offset = note_value(bytes, at + word * 2, word, header.order);
        require(start < end, "ELF NT_FILE mapping has an empty or reversed address range");
        require(page_offset <= UINT64_MAX / page_size, "ELF NT_FILE file offset overflows");
        const auto terminator = std::find(bytes.begin() + static_cast<std::ptrdiff_t>(path_cursor), bytes.end(), std::byte{0});
        require(terminator != bytes.end(), "ELF NT_FILE path list is truncated");
        const auto path_end = static_cast<std::size_t>(terminator - bytes.begin());
        std::string path(reinterpret_cast<const char *>(bytes.data() + path_cursor), path_end - path_cursor);
        rows.push_back({start, end, page_offset * page_size, note.file_offset,
                        note.description_file_offset + at, std::move(path)});
        path_cursor = path_end + 1;
    }
    budget.include(rows.size() * sizeof(ElfCoreFileMapping));
    for (const auto &row : rows) budget.include(row.path.size());
    core.file_mappings.insert(core.file_mappings.end(), std::make_move_iterator(rows.begin()),
                              std::make_move_iterator(rows.end()));
}

void read_signal_info(const ElfHeader &header, const ElfNote &note,
                      ElfCoreInfo &core, Budget &budget) {
    const auto bytes = std::span<const std::byte>(note.description);
    require(bytes.size() >= 3 * sizeof(std::uint32_t), "ELF NT_SIGINFO payload is shorter than siginfo header");
    const auto signed32 = [&](std::size_t at) {
        return static_cast<std::int32_t>(static_cast<std::uint32_t>(
            note_value(bytes, at, sizeof(std::uint32_t), header.order)));
    };
    ElfCoreSignalInfo info;
    info.signal = signed32(0);
    info.error = signed32(4);
    info.code = signed32(8);
    info.note_file_offset = note.file_offset;
    info.payload_file_offset = note.description_file_offset;
    // Linux places si_addr in the fault-specific union for SIGILL, SIGTRAP,
    // SIGBUS, SIGFPE, and SIGSEGV. Its offset follows the class ABI alignment.
    if (info.signal == 4 || info.signal == 5 || info.signal == 7 || info.signal == 8 || info.signal == 11) {
        const std::size_t address_offset = header.is_64 ? 16 : 12;
        const std::size_t word = header.is_64 ? 8 : 4;
        require(bytes.size() >= address_offset + word, "ELF NT_SIGINFO fault address is truncated");
        info.fault_address = note_value(bytes, address_offset, word, header.order);
    }
    budget.include(sizeof(ElfCoreSignalInfo));
    core.signal_info.push_back(std::move(info));
}
} // namespace

void read_core_notes(ElfMetadata &metadata, Budget &budget, std::stop_token stop) {
    if (metadata.header.object_type != et_core)
        return;
    ElfCoreInfo core;
    for (const auto &program : metadata.programs) {
        canceled(stop);
        if (program.type == 1 && program.memory_size)
            ++core.load_segment_count;
    }
    for (const auto &note : metadata.notes) {
        canceled(stop);
        if (!note.program)
            continue;
        if (!linux_core_note(note))
            continue;
        if (note.type == nt_prpsinfo)
            read_process_info(metadata.header, note, core, budget);
        else if (note.type == nt_prstatus)
            read_thread_status(metadata.header, note, core, budget);
        else if (note.type == nt_auxv || note.type == nt_file || note.type == nt_siginfo) {
            try {
                if (note.type == nt_auxv)
                    read_auxiliary_values(metadata.header, note, core, budget, stop);
                else if (note.type == nt_file)
                    read_file_mappings(metadata.header, note, core, budget, stop);
                else
                    read_signal_info(metadata.header, note, core, budget);
            } catch (const Failure &failure) {
                if (failure.error.code == ErrorCode::canceled)
                    throw;
                const auto label = note.type == nt_auxv ? "ELF NT_AUXV: "
                                   : note.type == nt_file ? "ELF NT_FILE: " : "ELF NT_SIGINFO: ";
                diagnostic(core, budget, std::string(label) + failure.error.message);
            }
        }
    }
    budget.include(sizeof(ElfCoreInfo));
    metadata.core = std::move(core);
}
} // namespace hexlab::elf_detail
