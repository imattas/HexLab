#include "type_editor.hpp"

#include "hexlab/types/enum_authoring.hpp"
#include "hexlab/types/types.hpp"
#include "data_views.hpp"

#include <wx/button.h>
#include <wx/checkbox.h>
#include <wx/choice.h>
#include <wx/dialog.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>

#include <algorithm>
#include <bit>
#include <charconv>
#include <functional>
#include <limits>
#include <sstream>
#include <utility>

namespace hexlab::desktop {
namespace {

enum class EditorKind { integer, boolean, floating, pointer, array, enumeration, function, structure, union_type };

std::string utf8_value(const wxString &value) {
    const auto encoded = value.utf8_str();
    return {encoded.data(), encoded.length()};
}

bool parse_number(std::string text, std::uint64_t &value) {
    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.erase(0, 2);
        base = 16;
    }
    if (text.empty()) return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}

int kind_index(types::Kind kind) {
    switch (kind) {
    case types::Kind::integer: return 0;
    case types::Kind::boolean: return 1;
    case types::Kind::floating: return 2;
    case types::Kind::pointer: return 3;
    case types::Kind::array: return 4;
    case types::Kind::enumeration: return 5;
    case types::Kind::function: return 6;
    case types::Kind::structure: return 7;
    case types::Kind::union_type: return 8;
    default: return 0;
    }
}

std::string signed_enum_value(std::uint64_t value, std::uint64_t size) {
    if (size < 8) {
        const auto bits = static_cast<unsigned>(size * 8);
        if (bits && (value & (UINT64_C(1) << (bits - 1))))
            value |= ~((UINT64_C(1) << bits) - 1);
    }
    return std::to_string(std::bit_cast<std::int64_t>(value));
}

std::uint64_t project_pointer_size(const ProjectSnapshot &project) {
    if (project.loaded && project.loaded->image) {
        const auto &layout = project.loaded->image->layout();
        if (layout.stack_address_width == 16 || layout.stack_address_width == 32 ||
            layout.stack_address_width == 64)
            return layout.stack_address_width / 8;
        switch (layout.mode) {
        case ExecutionMode::x86_16:
        case ExecutionMode::m6502: return 2;
        case ExecutionMode::x86_32:
        case ExecutionMode::a32:
        case ExecutionMode::thumb:
        case ExecutionMode::rv32:
        case ExecutionMode::mips32:
        case ExecutionMode::ppc32: return 4;
        case ExecutionMode::x86_64:
        case ExecutionMode::a64:
        case ExecutionMode::rv64:
        case ExecutionMode::rv64c:
        case ExecutionMode::mips64:
        case ExecutionMode::ppc64: return 8;
        default: break;
        }
        switch (layout.architecture) {
        case Architecture::x86:
        case Architecture::arm:
        case Architecture::riscv32:
        case Architecture::mips32: return 4;
        case Architecture::x86_64:
        case Architecture::arm64:
        case Architecture::riscv64:
        case Architecture::mips64: return 8;
        case Architecture::powerpc: return 4;
        case Architecture::wasm:
        case Architecture::dex: return 4;
        case Architecture::mos6502: return 2;
        default: break;
        }
    }
    return 8;
}

std::string member_type_name(const types::TypePtr &type,
                             const std::vector<database::TypeDefinition> &definitions) {
    if (!type) return {};
    const auto has_qualified = [&](const auto &self, const types::TypePtr &current) -> bool {
        if (!current) return false;
        if (current->kind() == types::Kind::qualified) return true;
        if ((current->kind() == types::Kind::pointer || current->kind() == types::Kind::array) && current->element())
            return self(self, current->element());
        return false;
    };
    const auto has_overaligned_array = [&](const auto &self, const types::TypePtr &current) -> bool {
        if (!current) return false;
        if (current->kind() == types::Kind::array && current->element() &&
            current->alignment() != current->element()->alignment()) return true;
        if ((current->kind() == types::Kind::pointer || current->kind() == types::Kind::array ||
             current->kind() == types::Kind::qualified) && current->element())
            return self(self, current->element());
        return false;
    };
    if (has_qualified(has_qualified, type) || has_overaligned_array(has_overaligned_array, type)) {
        const auto encode = [&](const auto &self, const types::TypePtr &current) -> std::string {
            const auto definition = std::find_if(definitions.begin(), definitions.end(), [&](const auto &item) {
                return item.type && item.type->id() == current->id();
            });
            if (definition != definitions.end())
                return "N" + std::to_string(definition->name.size()) + ":" + definition->name;
            if (current->kind() == types::Kind::named_reference)
                return "N" + std::to_string(current->name().size()) + ":" + current->name();
            if (current->kind() == types::Kind::pointer && current->element())
                return "P" + std::to_string(current->size().value_or(0)) + "," +
                       std::to_string(current->alignment()) + "(" + self(self, current->element()) + ")";
            if (current->kind() == types::Kind::array && current->element())
                return "A" + std::to_string(current->count()) + "," + std::to_string(current->alignment()) +
                       "(" + self(self, current->element()) + ")";
            if (current->kind() == types::Kind::qualified && current->element())
                return "Q" + std::to_string(current->qualifiers()) + "(" + self(self, current->element()) + ")";
            return "N" + std::to_string(current->name().size()) + ":" + current->name();
        };
        return "$" + encode(encode, type);
    }
    const auto direct = std::find_if(definitions.begin(), definitions.end(), [&](const auto &item) {
        return item.type && item.type->id() == type->id();
    });
    if (direct != definitions.end()) return direct->name;
    const auto render = [&](const auto &self, const types::TypePtr &current) -> std::string {
        if (!current) return {};
        const auto definition = std::find_if(definitions.begin(), definitions.end(), [&](const auto &item) {
            return item.type && item.type->id() == current->id();
        });
        if (definition != definitions.end()) return definition->name;
        if (current->kind() == types::Kind::named_reference) return current->name();
        if (current->kind() == types::Kind::pointer && current->element())
            return self(self, current->element()) + "*";
        if (current->kind() == types::Kind::array && current->element())
            return self(self, current->element()) + "[" +
                   (current->count() ? std::to_string(current->count()) : std::string{}) + "]";
        if (current->kind() == types::Kind::qualified && current->element()) {
            std::string qualifier;
            if (current->qualifiers() & static_cast<std::uint8_t>(types::Qualifier::const_)) qualifier += "const ";
            if (current->qualifiers() & static_cast<std::uint8_t>(types::Qualifier::volatile_)) qualifier += "volatile ";
            if (current->qualifiers() & static_cast<std::uint8_t>(types::Qualifier::restrict_)) qualifier += "restrict ";
            qualifier.pop_back();
            const auto base = self(self, current->element());
            return current->element()->kind() == types::Kind::pointer ? base + " " + qualifier
                                                                      : qualifier + " " + base;
        }
        const auto found = std::find_if(definitions.begin(), definitions.end(), [&](const auto &item) {
            return item.type && item.type->id() == current->id();
        });
        return found != definitions.end() ? found->name : current->name();
    };
    return render(render, type);
}

std::uint64_t choice_width(const wxChoice &choice) {
    const auto selection = choice.GetSelection();
    return selection >= 0 ? (UINT64_C(1) << selection) : 0;
}

} // namespace

std::optional<TypeEditorResult> show_type_editor(
    wxWindow *parent, const ProjectSnapshot &project,
    const database::TypeDefinition *original, int initial_kind) {
    if (!project.state) return {};
    const auto &definitions = project.state->user->types;
    if (original && std::none_of(definitions.begin(), definitions.end(), [&](const auto &item) {
            return item.id == original->id;
        })) return {};

    wxDialog dialog(parent, wxID_ANY, original ? "Edit project type" : "New project type",
                    wxDefaultPosition, wxDefaultSize, wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
    dialog.SetName("project-type-editor");
    auto *root = new wxBoxSizer(wxVERTICAL);
    auto *form = new wxFlexGridSizer(2, dialog.FromDIP(8), dialog.FromDIP(8));
    form->AddGrowableCol(1, 1);

    auto *name = new wxTextCtrl(&dialog, wxID_ANY, original ? text(original->name) : wxString("my_type"));
    name->SetName("type-editor-name");
    auto *kind = new wxChoice(&dialog, wxID_ANY);
    kind->SetName("type-editor-kind");
    for (const auto *label : {"Integer", "Boolean", "Floating point", "Pointer", "Fixed array",
                              "Enumeration", "Function prototype", "Structure", "Union"})
        kind->Append(label);
    auto *width = new wxChoice(&dialog, wxID_ANY);
    width->SetName("type-editor-width");
    for (const auto *label : {"1 byte", "2 bytes", "4 bytes", "8 bytes"}) width->Append(label);
    auto *signed_value = new wxCheckBox(&dialog, wxID_ANY, "Signed integer");
    signed_value->SetName("type-editor-signed");
    auto *reference = new wxChoice(&dialog, wxID_ANY);
    reference->SetName("type-editor-reference");
    auto *count = new wxTextCtrl(&dialog, wxID_ANY, "4");
    count->SetName("type-editor-count");
    auto *member_pointer_width = new wxChoice(&dialog, wxID_ANY);
    member_pointer_width->SetName("type-editor-member-pointer-width");
    for (const auto *label : {"1 byte", "2 bytes", "4 bytes", "8 bytes"})
        member_pointer_width->Append(label);
    auto *deferred_size = new wxTextCtrl(&dialog, wxID_ANY, "");
    deferred_size->SetName("type-editor-deferred-aggregate-size");
    auto *variadic = new wxCheckBox(&dialog, wxID_ANY, "Variadic prototype");
    variadic->SetName("type-editor-variadic");
    auto *convention = new wxChoice(&dialog, wxID_ANY);
    convention->SetName("type-editor-convention");
    for (const auto *label : {"Platform default", "cdecl", "stdcall", "fastcall", "thiscall",
                              "vectorcall", "sysv_abi", "ms_abi", "aapcs64"})
        convention->Append(label);
    auto *details_label = new wxStaticText(&dialog, wxID_ANY, "Definition");
    auto *details = new wxTextCtrl(&dialog, wxID_ANY, {}, wxDefaultPosition, dialog.FromDIP(wxSize(-1, 190)),
                                   wxTE_MULTILINE | wxTE_DONTWRAP);
    details->SetName("type-editor-details");
    auto add_row = [&](const wxString &label, wxWindow *control) {
        form->Add(new wxStaticText(&dialog, wxID_ANY, label), 0, wxALIGN_CENTER_VERTICAL);
        form->Add(control, 1, wxEXPAND);
    };
    add_row("Name", name);
    add_row("Kind", kind);
    add_row("Storage width", width);
    form->Add(new wxStaticText(&dialog, wxID_ANY, "Integer format"), 0, wxALIGN_CENTER_VERTICAL);
    form->Add(signed_value, 1, wxEXPAND);
    add_row("Referenced type", reference);
    add_row("Element count", count);
    auto *member_pointer_width_label = new wxStaticText(&dialog, wxID_ANY, "Member pointer width");
    form->Add(member_pointer_width_label, 0, wxALIGN_CENTER_VERTICAL);
    form->Add(member_pointer_width, 1, wxEXPAND);
    auto *deferred_size_label = new wxStaticText(&dialog, wxID_ANY, "Stored size for forward members");
    form->Add(deferred_size_label, 0, wxALIGN_CENTER_VERTICAL);
    form->Add(deferred_size, 1, wxEXPAND);
    form->Add(new wxStaticText(&dialog, wxID_ANY, "Prototype"), 0, wxALIGN_CENTER_VERTICAL);
    form->Add(variadic, 1, wxEXPAND);
    add_row("Calling convention", convention);
    form->Add(details_label, 0, wxALIGN_CENTER_VERTICAL);
    form->Add(details, 1, wxEXPAND);
    root->Add(form, 1, wxEXPAND | wxALL, dialog.FromDIP(10));
    auto *error = new wxStaticText(&dialog, wxID_ANY, "");
    error->SetName("type-editor-error");
    root->Add(error, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, dialog.FromDIP(8));
    auto *buttons = new wxStdDialogButtonSizer();
    auto *save = new wxButton(&dialog, wxID_OK, "Save type");
    auto *cancel = new wxButton(&dialog, wxID_CANCEL, "Cancel");
    buttons->AddButton(save); buttons->AddButton(cancel); buttons->Realize();
    root->Add(buttons, 0, wxEXPAND | wxALL, dialog.FromDIP(8));
    dialog.SetSizerAndFit(root);
    dialog.SetMinSize(dialog.FromDIP(wxSize(560, 530)));

    int initial = initial_kind >= 0 && initial_kind <= 8 ? initial_kind : 0;
    if (original) initial = kind_index(original->type->kind());
    kind->SetSelection(initial);
    width->SetSelection(2);
    convention->SetSelection(0);
    const auto default_pointer_size = project_pointer_size(project);
    const auto select_width = [](wxChoice &choice, std::uint64_t bytes) {
        const int index = bytes == 1 ? 0 : bytes == 2 ? 1 : bytes == 4 ? 2 : bytes == 8 ? 3 : 3;
        choice.SetSelection(index);
    };
    select_width(*member_pointer_width, default_pointer_size);

    std::vector<const database::TypeDefinition *> references;
    std::string wanted_reference;
    auto rebuild_references = [&] {
        references.clear();
        reference->Clear();
        const auto selected_kind = static_cast<EditorKind>(kind->GetSelection());
        const bool allow_void = selected_kind == EditorKind::function;
        const bool integer_only = selected_kind == EditorKind::enumeration;
        if (allow_void) reference->Append("void");
        for (const auto &item : definitions) {
            if (original && item.id == original->id) continue;
            if (integer_only && item.type->kind() != types::Kind::integer) continue;
            references.push_back(&item);
            reference->Append(text(item.name));
        }
        int selected = allow_void ? 0 : wxNOT_FOUND;
        for (std::size_t i = 0; i < references.size(); ++i)
            if (references[i]->name == wanted_reference)
                selected = static_cast<int>(i) + (allow_void ? 1 : 0);
        if (selected == wxNOT_FOUND && reference->GetCount()) selected = 0;
        if (selected != wxNOT_FOUND) reference->SetSelection(selected);
    };
    auto update_controls = [&] {
        const auto selected_kind = static_cast<EditorKind>(kind->GetSelection());
        const bool scalar_width = selected_kind <= EditorKind::floating || selected_kind == EditorKind::pointer;
        const bool integer = selected_kind == EditorKind::integer;
        const bool has_reference = selected_kind == EditorKind::pointer || selected_kind == EditorKind::array ||
                                   selected_kind == EditorKind::enumeration || selected_kind == EditorKind::function;
        const bool has_count = selected_kind == EditorKind::array;
        const bool is_function = selected_kind == EditorKind::function;
        const bool is_aggregate = selected_kind == EditorKind::structure || selected_kind == EditorKind::union_type;
        const bool needs_details = selected_kind == EditorKind::enumeration || is_function ||
                                   selected_kind == EditorKind::structure || selected_kind == EditorKind::union_type;
        width->Show(scalar_width);
        signed_value->Show(integer);
        reference->Show(has_reference);
        count->Show(has_count);
        member_pointer_width_label->Show(is_aggregate);
        member_pointer_width->Show(is_aggregate);
        deferred_size_label->Show(is_aggregate);
        deferred_size->Show(is_aggregate);
        variadic->Show(is_function);
        convention->Show(is_function);
        details_label->Show(needs_details);
        details->Show(needs_details);
        if (selected_kind == EditorKind::enumeration)
            details_label->SetLabel("Enumerators (NAME or NAME = VALUE)");
        else if (is_function)
            details_label->SetLabel("Parameters (one per line: name type_name)");
        else if (selected_kind == EditorKind::union_type)
            details_label->SetLabel("Members: name type_name [bit_width bit_offset]; use TypeName* for pointers");
        else if (selected_kind == EditorKind::structure)
            details_label->SetLabel("Members: name type_name byte_offset [bit_width bit_offset]; use TypeName* for pointers");
        dialog.Layout();
        dialog.Fit();
    };
    kind->Bind(wxEVT_CHOICE, [&](wxCommandEvent &) { wanted_reference.clear(); rebuild_references(); update_controls(); });
    rebuild_references();

    if (original) {
        const auto &type = *original->type;
        auto reference_name = [&](const types::TypePtr &reference_type) {
            const auto found = std::find_if(definitions.begin(), definitions.end(), [&](const auto &item) {
                return item.type->id() == reference_type->id();
            });
            return found == definitions.end() ? reference_type->name() : found->name;
        };
        if (type.size()) {
            const auto size = *type.size();
            if (size == 1 || size == 2 || size == 4 || size == 8)
                width->SetSelection(size == 1 ? 0 : size == 2 ? 1 : size == 4 ? 2 : 3);
        }
        signed_value->SetValue(type.is_signed());
        if (type.element()) wanted_reference = reference_name(type.element());
        if (type.result_type()) wanted_reference = type.result_type()->kind() == types::Kind::void_type
            ? "void" : reference_name(type.result_type());
        if (type.kind() == types::Kind::enumeration && type.element())
            wanted_reference = reference_name(type.element());
        if (type.kind() == types::Kind::array) count->SetValue(wxString::Format("%llu", static_cast<unsigned long long>(type.count())));
        if (type.kind() == types::Kind::function) {
            variadic->SetValue(type.variadic());
            convention->SetSelection(static_cast<int>(type.function_convention()));
            std::ostringstream out;
            for (const auto &parameter : type.parameters()) out << parameter.name << ' ' << reference_name(parameter.type) << '\n';
            details->SetValue(text(out.str()));
        } else if (type.kind() == types::Kind::enumeration) {
            std::ostringstream out;
            for (const auto &enumerator : type.enumerator_values()) {
                if (out.tellp() > 0) out << ", ";
                out << enumerator.name << " = "
                    << (type.element()->is_signed() ? signed_enum_value(enumerator.value, type.element()->size().value_or(8))
                                                    : std::to_string(enumerator.value));
            }
            details->SetValue(text(out.str()));
        } else if (type.kind() == types::Kind::structure || type.kind() == types::Kind::union_type) {
            std::ostringstream out;
            for (const auto &member : type.members()) {
                out << member.name << ' ' << member_type_name(member.type, definitions);
                if (type.kind() == types::Kind::structure) out << ' ' << member.offset;
                if (member.bit_width) out << ' ' << *member.bit_width << ' ' << *member.bit_offset;
                out << '\n';
                auto pointed = member.type;
                while (pointed && pointed->kind() == types::Kind::pointer && pointed->element()) {
                    if (pointed->size()) select_width(*member_pointer_width, *pointed->size());
                    pointed = pointed->element();
                }
                if (pointed && pointed->kind() == types::Kind::named_reference &&
                    !member.type->size() && type.size())
                    deferred_size->SetValue(wxString::Format("%llu", static_cast<unsigned long long>(*type.size())));
            }
            details->SetValue(text(out.str()));
        }
        rebuild_references();
    }
    update_controls();

    std::optional<TypeEditorResult> result;
    dialog.Bind(wxEVT_BUTTON, [&](wxCommandEvent &) {
        const auto clean_name = utf8_value(name->GetValue());
        if (clean_name.empty() || clean_name.size() > 512) {
            error->SetLabel("Type name is required and limited to 512 UTF-8 bytes."); return;
        }
        if (std::any_of(definitions.begin(), definitions.end(), [&](const auto &item) {
                return item.name == clean_name && (!original || item.id != original->id);
            })) {
            error->SetLabel("Another project type already has this name."); return;
        }
        const auto selected_kind = static_cast<EditorKind>(kind->GetSelection());
        if (details->GetValue().length() > 1024 * 1024) {
            error->SetLabel("Type details are limited to 1 MiB of text."); return;
        }
        const auto width_index = width->GetSelection();
        const std::uint64_t size = width_index >= 0 ? (UINT64_C(1) << width_index) : 0;
        auto selected_reference = [&]() -> types::TypePtr {
            const auto index = reference->GetSelection();
            if (index == wxNOT_FOUND) return {};
            if (selected_kind == EditorKind::function) {
                if (index == 0) return types::Type::void_type();
                const auto adjusted = static_cast<std::size_t>(index - 1);
                return adjusted < references.size() ? references[adjusted]->type : types::TypePtr{};
            }
            const auto adjusted = static_cast<std::size_t>(index);
            return adjusted < references.size() ? references[adjusted]->type : types::TypePtr{};
        };
        types::TypePtr made;
        std::string problem;
        if (selected_kind == EditorKind::integer) {
            auto value = types::Type::integer(clean_name, size, size, signed_value->GetValue());
            if (value) made = value.value(); else problem = value.error().message;
        } else if (selected_kind == EditorKind::boolean) {
            auto value = types::Type::boolean(size, size);
            if (value) made = value.value(); else problem = value.error().message;
        } else if (selected_kind == EditorKind::floating) {
            auto value = types::Type::floating(clean_name, size, size);
            if (value) made = value.value(); else problem = value.error().message;
        } else if (selected_kind == EditorKind::pointer) {
            auto pointee = selected_reference();
            if (!pointee) problem = "Choose a pointee type.";
            else { auto value = types::Type::pointer(pointee, size, size); if (value) made = value.value(); else problem = value.error().message; }
        } else if (selected_kind == EditorKind::array) {
            auto element = selected_reference();
            std::uint64_t elements = 0;
            if (!element) problem = "Choose an array element type.";
            else if (!parse_number(utf8_value(count->GetValue()), elements) || elements == 0)
                problem = "Fixed array count must be a positive decimal or hexadecimal integer.";
            else { auto value = types::Type::array(element, elements); if (value) made = value.value(); else problem = value.error().message; }
        } else if (selected_kind == EditorKind::enumeration) {
            auto underlying = selected_reference();
            if (!underlying) problem = "Choose an integer underlying type.";
            else {
                auto parsed = types::parse_enumerators(utf8_value(details->GetValue()), underlying);
                if (!parsed) problem = parsed.error().message;
                else { auto value = types::Type::enumeration_with_values(clean_name, underlying, std::move(parsed.value()));
                    if (value) made = value.value(); else problem = value.error().message; }
            }
        } else if (selected_kind == EditorKind::function) {
            auto return_type = selected_reference();
            std::vector<types::Parameter> parameters;
            std::istringstream lines(utf8_value(details->GetValue()));
            std::string line;
            while (problem.empty() && std::getline(lines, line)) {
                if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue;
                std::istringstream fields(line);
                std::string parameter_name, type_name, extra;
                if (!(fields >> parameter_name >> type_name) || (fields >> extra)) {
                    problem = "Each parameter line must contain exactly: name type_name."; break;
                }
                const auto found = std::find_if(definitions.begin(), definitions.end(), [&](const auto &item) {
                    return item.name == type_name && (!original || item.id != original->id);
                });
                if (found == definitions.end()) { problem = "Unknown parameter type: " + type_name; break; }
                parameters.push_back({std::move(parameter_name), found->type});
            }
            if (!return_type) problem = "Choose a function return type.";
            if (problem.empty()) {
                static constexpr types::FunctionConvention conventions[] = {
                    types::FunctionConvention::platform_default, types::FunctionConvention::c_decl,
                    types::FunctionConvention::stdcall, types::FunctionConvention::fastcall,
                    types::FunctionConvention::thiscall, types::FunctionConvention::vectorcall,
                    types::FunctionConvention::sysv_abi, types::FunctionConvention::ms_abi,
                    types::FunctionConvention::aapcs64};
                const auto convention_index = std::clamp(convention->GetSelection(), 0, 8);
                auto value = types::Type::function(return_type, std::move(parameters), variadic->GetValue(),
                                                   conventions[convention_index]);
                if (value) made = value.value(); else problem = value.error().message;
            }
        } else {
            const bool is_union = selected_kind == EditorKind::union_type;
            const auto packing = original ? original->type->packing_alignment() : std::nullopt;
            std::vector<types::Member> members;
            std::istringstream lines(utf8_value(details->GetValue()));
            std::string line;
            std::uint64_t total_size = 0, alignment = 1;
            std::uint64_t deferred_minimum_extent = 0;
            bool has_deferred_by_value = false;
            const auto pointer_bytes = choice_width(*member_pointer_width);
            auto resolve_member_type = [&](std::string type_name) -> types::TypePtr {
                if (type_name.starts_with('$')) {
                    if (type_name.size() > 4096) {
                        problem = "Encoded member type exceeds 4096 bytes.";
                        return {};
                    }
                    std::size_t cursor = 1;
                    std::function<types::TypePtr(std::size_t)> parse_encoded = [&](std::size_t depth) -> types::TypePtr {
                        if (depth >= 64 || cursor >= type_name.size()) {
                            problem = "Encoded member type is truncated or nested too deeply.";
                            return {};
                        }
                        const auto tag = type_name[cursor++];
                        std::uint64_t value = 0;
                        if (tag == 'N') {
                            const auto digits = cursor;
                            while (cursor < type_name.size() && type_name[cursor] >= '0' && type_name[cursor] <= '9')
                                ++cursor;
                            if (digits == cursor) {
                                problem = "Encoded member type has an invalid name length.";
                                return {};
                            }
                            std::size_t length = 0;
                            const auto parsed = std::from_chars(type_name.data() + digits,
                                                                type_name.data() + cursor, length);
                            if (parsed.ec != std::errc{} || cursor >= type_name.size() || type_name[cursor++] != ':' ||
                                length > 512 || length > type_name.size() - cursor) {
                                problem = "Encoded member type has an invalid name length.";
                                return {};
                            }
                            auto name = type_name.substr(cursor, length);
                            cursor += length;
                            const auto found = std::find_if(definitions.begin(), definitions.end(), [&](const auto &item) {
                                return item.name == name && (!original || item.id != original->id);
                            });
                            if (found != definitions.end()) return found->type;
                            auto reference = types::Type::named_reference(std::move(name));
                            if (!reference) { problem = reference.error().message; return {}; }
                            return std::move(reference.value());
                        }
                        std::uint64_t pointer_size = 0, pointer_alignment = 0, array_alignment = 0;
                        if (tag == 'P') {
                            const auto size_begin = cursor;
                            while (cursor < type_name.size() && type_name[cursor] >= '0' && type_name[cursor] <= '9') ++cursor;
                            if (size_begin == cursor || cursor >= type_name.size() || type_name[cursor++] != ',') {
                                problem = "Encoded pointer type has an invalid size.";
                                return {};
                            }
                            auto parsed_size = std::from_chars(type_name.data() + size_begin,
                                                               type_name.data() + cursor - 1, pointer_size);
                            const auto alignment_begin = cursor;
                            while (cursor < type_name.size() && type_name[cursor] >= '0' && type_name[cursor] <= '9') ++cursor;
                            if (parsed_size.ec != std::errc{} || alignment_begin == cursor) {
                                problem = "Encoded pointer type has an invalid alignment.";
                                return {};
                            }
                            auto parsed_alignment = std::from_chars(type_name.data() + alignment_begin,
                                                                    type_name.data() + cursor, pointer_alignment);
                            if (parsed_alignment.ec != std::errc{}) {
                                problem = "Encoded pointer type has an invalid alignment.";
                                return {};
                            }
                        } else if (tag == 'A') {
                            const auto count_begin = cursor;
                            while (cursor < type_name.size() && type_name[cursor] >= '0' && type_name[cursor] <= '9') ++cursor;
                            if (count_begin == cursor || cursor >= type_name.size() || type_name[cursor++] != ',') {
                                problem = "Encoded array type has an invalid count.";
                                return {};
                            }
                            const auto parsed_count = std::from_chars(type_name.data() + count_begin,
                                                                      type_name.data() + cursor - 1, value);
                            const auto alignment_begin = cursor;
                            while (cursor < type_name.size() && type_name[cursor] >= '0' && type_name[cursor] <= '9') ++cursor;
                            if (parsed_count.ec != std::errc{} || alignment_begin == cursor) {
                                problem = "Encoded array type has an invalid alignment.";
                                return {};
                            }
                            const auto parsed_alignment = std::from_chars(type_name.data() + alignment_begin,
                                                                           type_name.data() + cursor, array_alignment);
                            if (parsed_alignment.ec != std::errc{} || array_alignment == 0) {
                                problem = "Encoded array type has an invalid alignment.";
                                return {};
                            }
                        } else {
                            const auto digits = cursor;
                            while (cursor < type_name.size() && type_name[cursor] >= '0' && type_name[cursor] <= '9')
                                ++cursor;
                            if (digits == cursor) {
                                problem = "Encoded member type has an invalid constructor value.";
                                return {};
                            }
                            const auto parsed = std::from_chars(type_name.data() + digits,
                                                                type_name.data() + cursor, value);
                            if (parsed.ec != std::errc{}) {
                                problem = "Encoded member type has an invalid constructor value.";
                                return {};
                            }
                        }
                        if (cursor >= type_name.size() || type_name[cursor++] != '(') {
                            problem = "Encoded member type has an invalid constructor.";
                            return {};
                        }
                        auto element = parse_encoded(depth + 1);
                        if (!element || cursor >= type_name.size() || type_name[cursor++] != ')') {
                            if (problem.empty()) problem = "Encoded member type has an unterminated constructor.";
                            return {};
                        }
                        if (tag == 'P') {
                            auto pointer = types::Type::pointer(std::move(element), pointer_size, pointer_alignment);
                            if (!pointer) { problem = pointer.error().message; return {}; }
                            return std::move(pointer.value());
                        }
                        if (tag == 'A') {
                            auto array = types::Type::array(std::move(element), value);
                            if (!array) { problem = array.error().message; return {}; }
                            auto aligned = types::Type::with_alignment(std::move(array.value()), array_alignment);
                            if (!aligned) { problem = aligned.error().message; return {}; }
                            return std::move(aligned.value());
                        }
                        if (tag == 'Q') {
                            if (value > UINT8_MAX) { problem = "Encoded member qualifier mask is invalid."; return {}; }
                            auto qualified = types::Type::qualified(std::move(element), static_cast<std::uint8_t>(value));
                            if (!qualified) { problem = qualified.error().message; return {}; }
                            return std::move(qualified.value());
                        }
                        problem = "Encoded member type has an unknown constructor.";
                        return {};
                    };
                    auto encoded_type = parse_encoded(0);
                    if (!encoded_type || cursor != type_name.size()) {
                        if (problem.empty()) problem = "Encoded member type has trailing data.";
                        return {};
                    }
                    return encoded_type;
                }
                bool flexible_array = false;
                if (type_name.size() >= 2 && type_name.ends_with("[]")) {
                    type_name.resize(type_name.size() - 2);
                    flexible_array = true;
                }
                std::uint8_t element_qualifiers = 0, pointer_qualifiers = 0;
                const auto qualifier = [](std::string_view word) -> std::uint8_t {
                    if (word == "const") return static_cast<std::uint8_t>(types::Qualifier::const_);
                    if (word == "volatile") return static_cast<std::uint8_t>(types::Qualifier::volatile_);
                    if (word == "restrict") return static_cast<std::uint8_t>(types::Qualifier::restrict_);
                    return 0;
                };
                std::istringstream type_fields(type_name);
                std::vector<std::string> type_words;
                for (std::string word; type_fields >> word;) type_words.push_back(std::move(word));
                std::size_t first = 0, last = type_words.size();
                while (first < last) {
                    const auto bits = qualifier(type_words[first]);
                    if (!bits) break;
                    element_qualifiers |= bits;
                    ++first;
                }
                while (last > first) {
                    const auto bits = qualifier(type_words[last - 1]);
                    if (!bits) break;
                    pointer_qualifiers |= bits;
                    --last;
                }
                std::ostringstream base_name;
                for (std::size_t i = first; i < last; ++i) {
                    if (i != first) base_name << ' ';
                    base_name << type_words[i];
                }
                type_name = base_name.str();
                std::size_t pointer_depth = 0;
                while (!type_name.empty() && type_name.back() == '*') {
                    type_name.pop_back();
                    ++pointer_depth;
                }
                if (type_name.empty() || type_name.size() > 512) {
                    problem = "Member type name is empty or exceeds 512 bytes.";
                    return {};
                }
                const auto found = std::find_if(definitions.begin(), definitions.end(), [&](const auto &item) {
                    return item.name == type_name && (!original || item.id != original->id);
                });
                types::TypePtr member_type;
                if (found != definitions.end()) {
                    member_type = found->type;
                } else {
                    auto forward = types::Type::named_reference(type_name);
                    if (!forward) {
                        problem = forward.error().message;
                        return {};
                    }
                    member_type = std::move(forward.value());
                }
                if (element_qualifiers) {
                    auto qualified = types::Type::qualified(member_type, element_qualifiers);
                    if (!qualified) {
                        problem = qualified.error().message;
                        return {};
                    }
                    member_type = std::move(qualified.value());
                }
                if (pointer_depth && !pointer_bytes) {
                    problem = "Select a valid pointer width for inline pointer members.";
                    return {};
                }
                if (pointer_depth > 8) {
                    problem = "Member pointer nesting is limited to eight levels.";
                    return {};
                }
                for (std::size_t depth = 0; depth < pointer_depth; ++depth) {
                    auto pointer = types::Type::pointer(member_type, pointer_bytes, pointer_bytes);
                    if (!pointer) {
                        problem = pointer.error().message;
                        return {};
                    }
                    member_type = std::move(pointer.value());
                }
                if (pointer_qualifiers) {
                    auto qualified = types::Type::qualified(member_type, pointer_qualifiers);
                    if (!qualified) {
                        problem = qualified.error().message;
                        return {};
                    }
                    member_type = std::move(qualified.value());
                }
                if (flexible_array) {
                    auto array = types::Type::array(member_type, 0);
                    if (!array) {
                        problem = array.error().message;
                        return {};
                    }
                    member_type = std::move(array.value());
                }
                if (pointer_depth == 0 && !flexible_array && !member_type->size()) has_deferred_by_value = true;
                return member_type;
            };
            while (problem.empty() && std::getline(lines, line)) {
                if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue;
                if (members.size() >= 4096) { problem = "Aggregate is limited to 4096 members."; break; }
                std::istringstream fields(line);
                std::vector<std::string> columns;
                for (std::string column; fields >> column;) columns.push_back(std::move(column));
                if (columns.size() < (is_union ? 2u : 3u)) {
                    problem = is_union ? "Each union line must contain: name type_name [bit_width bit_offset]." :
                                         "Each structure line must contain: name type_name byte_offset [bit_width bit_offset].";
                    break;
                }
                const auto numeric = [](const std::string &text) {
                    std::uint64_t value = 0;
                    return parse_number(text, value);
                };
                std::string member_name = columns.front(), offset_text, width_text, bit_offset_text;
                bool has_width = false;
                std::size_t type_end = columns.size();
                if (is_union) {
                    if (columns.size() >= 4 && numeric(columns[columns.size() - 2]) && numeric(columns.back())) {
                        has_width = true;
                        width_text = columns[columns.size() - 2];
                        bit_offset_text = columns.back();
                        type_end -= 2;
                    }
                } else {
                    if (columns.size() >= 5 && numeric(columns[columns.size() - 3]) &&
                        numeric(columns[columns.size() - 2]) && numeric(columns.back())) {
                        has_width = true;
                        offset_text = columns[columns.size() - 3];
                        width_text = columns[columns.size() - 2];
                        bit_offset_text = columns.back();
                        type_end -= 3;
                    } else {
                        offset_text = columns.back();
                        --type_end;
                    }
                }
                if (type_end <= 1) { problem = "Member type name is empty."; break; }
                std::ostringstream type_name_builder;
                for (std::size_t i = 1; i < type_end; ++i) {
                    if (i != 1) type_name_builder << ' ';
                    type_name_builder << columns[i];
                }
                auto type_name = type_name_builder.str();
                std::uint64_t offset = 0;
                if (!is_union && !parse_number(offset_text, offset)) { problem = "Invalid member byte offset."; break; }
                std::optional<std::uint32_t> bit_width, bit_offset;
                if (has_width) {
                    std::uint64_t parsed_width = 0, parsed_offset = 0;
                    if (!parse_number(width_text, parsed_width) || !parse_number(bit_offset_text, parsed_offset) ||
                        !parsed_width || parsed_width > UINT32_MAX || parsed_offset > UINT32_MAX) {
                        problem = "Bitfield width and offset must be valid nonzero-width 32-bit values.";
                        break;
                    }
                    bit_width = static_cast<std::uint32_t>(parsed_width);
                    bit_offset = static_cast<std::uint32_t>(parsed_offset);
                }
                auto member_type = resolve_member_type(std::move(type_name));
                if (!member_type) { if (problem.empty()) problem = "Member type could not be resolved."; break; }
                auto layout_member_type = member_type;
                while (layout_member_type && layout_member_type->kind() == types::Kind::qualified &&
                       layout_member_type->element())
                    layout_member_type = layout_member_type->element();
                const bool flexible_array = layout_member_type && layout_member_type->kind() == types::Kind::array &&
                                            layout_member_type->count() == 0 && !layout_member_type->size();
                const auto member_size = member_type->size().value_or(0);
                if (offset > UINT64_MAX - member_size) { problem = "Member extent overflows."; break; }
                if (!member_size && !flexible_array) {
                    if (offset == UINT64_MAX) { problem = "Forward member minimum extent overflows."; break; }
                    deferred_minimum_extent = std::max(deferred_minimum_extent, offset + 1);
                }
                types::Member member{std::move(member_name), member_type, offset, bit_width, bit_offset};
                std::uint64_t member_alignment = member_type->alignment();
                if (packing) member_alignment = std::min(member_alignment, *packing);
                if (original && (selected_kind == EditorKind::structure || selected_kind == EditorKind::union_type)) {
                    const auto previous = std::find_if(original->type->members().begin(), original->type->members().end(),
                        [&](const auto &old) { return old.name == member.name && old.type->id() == member.type->id(); });
                    if (previous != original->type->members().end()) {
                        member.effective_alignment = previous->effective_alignment;
                        if (member.effective_alignment)
                            member_alignment = std::min(member_alignment, *member.effective_alignment);
                        if (previous->offset == member.offset && previous->bit_width == member.bit_width &&
                            previous->bit_offset == member.bit_offset) {
                            member.bit_width = previous->bit_width;
                            member.bit_offset = previous->bit_offset;
                        }
                    }
                }
                alignment = std::max(alignment, member_alignment);
                total_size = std::max(total_size, offset + member_size);
                if (!member_size) total_size = std::max(total_size, deferred_minimum_extent);
                members.push_back(std::move(member));
            }
            if (problem.empty() && members.empty()) problem = "An aggregate must contain at least one member.";
            if (problem.empty() && has_deferred_by_value) {
                const auto size_text = utf8_value(deferred_size->GetValue());
                std::uint64_t requested_size = 0;
                if (size_text.empty() || !parse_number(size_text, requested_size) || !requested_size)
                    problem = "Forward by-value members need a positive stored aggregate size (decimal or hexadecimal).";
                else if (requested_size < total_size)
                    problem = "Stored aggregate size is smaller than the known member extents.";
                else total_size = requested_size;
            }
            if (problem.empty()) {
                const auto remainder = total_size % alignment;
                if (remainder) {
                    const auto padding = alignment - remainder;
                    if (total_size > UINT64_MAX - padding) problem = "Aggregate tail padding overflows.";
                    else total_size += padding;
                }
            }
            if (problem.empty()) {
                auto value = is_union ? types::Type::union_type(clean_name, std::move(members), total_size, alignment, packing)
                                      : types::Type::structure(clean_name, std::move(members), total_size, alignment, packing);
                if (value) {
                    made = value.value();
                    if (original && !original->type->methods().empty()) {
                        auto retained = types::Type::with_methods(made, original->type->methods());
                        if (retained) made = std::move(retained).value();
                        else problem = retained.error().message;
                    }
                } else problem = value.error().message;
            }
        }
        if (!problem.empty()) { error->SetLabel(text(problem)); dialog.Layout(); return; }
        if (!made) { error->SetLabel("Type could not be created."); return; }
        result = TypeEditorResult{clean_name, std::move(made)};
        dialog.EndModal(wxID_OK);
    }, wxID_OK);
    dialog.Bind(wxEVT_BUTTON, [&](wxCommandEvent &) { dialog.EndModal(wxID_CANCEL); }, wxID_CANCEL);
    update_controls();
    if (dialog.ShowModal() != wxID_OK) return {};
    return result;
}

} // namespace hexlab::desktop

