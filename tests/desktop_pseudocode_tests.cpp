#include "pseudocode_view.hpp"
#include "support/desktop_test_window.hpp"
#include "project_view.hpp"
#include "type_symbols_view.hpp"

#include <wx/app.h>
#include <wx/frame.h>
#include <wx/listctrl.h>
#include <wx/textctrl.h>
#include <wx/button.h>
#include "hexlab/types/types.hpp"
#include <cstdio>
#include <stdexcept>

using namespace hexlab;
using namespace hexlab::desktop;

namespace {
class PseudocodeApp final : public wxApp {
    int result_ = 1;

  public:
    bool OnInit() override {
        wxSetAssertHandler([](const wxString &, int, const wxString &, const wxString &, const wxString &message) {
            std::fprintf(stderr, "wx assertion: %s\n", message.utf8_str().data());
            std::_Exit(4);
        });
        auto *frame = new wxFrame(nullptr, wxID_ANY, "Pseudocode test");
        auto *view = new PseudocodeView(frame);
        auto *type_symbols = new TypeSymbolsView(frame);
        frame->SetSize(900, 500);
        show_test_window(frame);
        CallAfter([this, frame, view, type_symbols] {
            try {
                const Address entry{{0}, 0x1000};
                RegisterOperand rax{RegisterBank::gpr, 0, 64, false};
                Instruction add;
                add.address = entry;
                add.length = 2;
                add.opcode = Opcode::add;
                add.operands = {rax, ImmediateOperand{2, 8, 64, false, {}}};
                Instruction ret;
                ret.address = Address{{0}, 0x1002};
                ret.length = 1;
                ret.opcode = Opcode::ret;
                ret.flow = FlowKind::ret;
                auto block = std::make_shared<BasicBlock>();
                block->id = BlockId{7};
                block->begin = entry;
                block->instructions = {
                    std::make_shared<InstructionFact>(InstructionFact{11, add, {}}),
                    std::make_shared<InstructionFact>(InstructionFact{12, ret, {}})};
                auto function = std::make_shared<FunctionRecord>();
                function->id = FunctionId{3};
                function->entry = entry;
                function->blocks = {BlockId{7}};
                auto stack_function = std::make_shared<FunctionRecord>();
                stack_function->id = FunctionId{4};
                stack_function->entry = Address{{0}, 0x2000};
                stack_function->blocks = {BlockId{8}};
                auto stack_block = std::make_shared<BasicBlock>();
                stack_block->id = BlockId{8};
                stack_block->begin = stack_function->entry;
                const auto stack_reg = [](std::uint8_t index) {
                    return RegisterOperand{RegisterBank::gpr, index, 64, false};
                };
                Instruction push;
                push.address = stack_function->entry;
                push.opcode = Opcode::push;
                push.context = {Architecture::x86_64, ExecutionMode::x86_64};
                push.stack_value_width = 64;
                push.operands = {stack_reg(5)};
                push.access = {OperandAccess::read};
                Instruction establish;
                establish.address = Address{{0}, 0x2001};
                establish.opcode = Opcode::mov;
                establish.context = push.context;
                establish.operands = {stack_reg(5), stack_reg(4)};
                establish.access = {OperandAccess::write, OperandAccess::read};
                Instruction allocate;
                allocate.address = Address{{0}, 0x2004};
                allocate.opcode = Opcode::sub;
                allocate.context = push.context;
                allocate.operands = {stack_reg(4), ImmediateOperand{16, 8, 64, false, {}}};
                allocate.access = {OperandAccess::read_write, OperandAccess::read};
                Instruction store;
                store.address = Address{{0}, 0x2008};
                store.opcode = Opcode::mov;
                store.context = push.context;
                MemoryOperand stack_memory;
                stack_memory.base = stack_reg(5);
                stack_memory.displacement = -8;
                stack_memory.data_width = 32;
                stack_memory.address_width = 64;
                store.operands = {stack_memory};
                store.access = {OperandAccess::write};
                Instruction stack_ret;
                stack_ret.address = Address{{0}, 0x200c};
                stack_ret.opcode = Opcode::ret;
                stack_ret.context = push.context;
                stack_ret.flow = FlowKind::ret;
                stack_block->instructions = {
                    std::make_shared<InstructionFact>(InstructionFact{21, push, {}}),
                    std::make_shared<InstructionFact>(InstructionFact{22, establish, {}}),
                    std::make_shared<InstructionFact>(InstructionFact{23, allocate, {}}),
                    std::make_shared<InstructionFact>(InstructionFact{24, store, {}}),
                    std::make_shared<InstructionFact>(InstructionFact{25, stack_ret, {}})};
                FunctionSnapshot snapshot;
                snapshot.functions = {function, stack_function};
                snapshot.blocks.push_back(block);
                snapshot.blocks.push_back(stack_block);
                const Address mask_entry{{0}, 0x3000};
                const RegisterOperand mask_register{RegisterBank::gpr, 0, 64, false};
                auto mask_block = std::make_shared<BasicBlock>();
                mask_block->id = BlockId{9};
                mask_block->begin = mask_entry;
                Instruction shift_left;
                shift_left.address = mask_entry;
                shift_left.context = {Architecture::x86_64, ExecutionMode::x86_64};
                shift_left.opcode = Opcode::shl;
                shift_left.operands = {mask_register, ImmediateOperand{2, 8, 64, false, {}}};
                shift_left.access = {OperandAccess::read_write, OperandAccess::read};
                Instruction shift_right = shift_left;
                shift_right.address = Address{{0}, 0x3001};
                shift_right.opcode = Opcode::shr;
                Instruction mask_ret;
                mask_ret.address = Address{{0}, 0x3002};
                mask_ret.context = shift_left.context;
                mask_ret.opcode = Opcode::ret;
                mask_ret.flow = FlowKind::ret;
                mask_block->instructions = {
                    std::make_shared<InstructionFact>(InstructionFact{31, shift_left, {}}),
                    std::make_shared<InstructionFact>(InstructionFact{32, shift_right, {}}),
                    std::make_shared<InstructionFact>(InstructionFact{33, mask_ret, {}})};
                auto mask_function = std::make_shared<FunctionRecord>();
                mask_function->id = FunctionId{5};
                mask_function->entry = mask_entry;
                mask_function->blocks = {mask_block->id};
                snapshot.functions.push_back(mask_function);
                snapshot.blocks.push_back(mask_block);

                auto project_state = std::make_shared<database::ProjectState>();
                auto user = std::make_shared<database::UserState>();
                user->annotations = {{1, entry, "calculate", "updates accumulator"},
                                     {3, Address{{0}, 0x2008}, "counter", {}}};
                auto scalar = types::Type::integer("u32", 4, 4, false).value();
                user->types.push_back({9, "u32", scalar});
                auto prior_type = types::Type::integer("u64", 8, 8, false).value();
                user->types.push_back({8, "u64", prior_type});
                user->type_assignments.push_back({10, entry, 8});
                project_state->user = user;
                auto project = std::make_shared<ProjectSnapshot>();
                project->state = project_state;
                project->mode = database::ProjectMode::read_write;
                database::DebugVariable debug_variable;
                debug_variable.id = 17;
                debug_variable.function_entry = entry;
                debug_variable.name = "local_value";
                debug_variable.cfa_offset = -16;
                debug_variable.location_expression = {0x91, 0x60};
                user->debug_variables.push_back(debug_variable);
                database::DebugVariable ranged_variable; ranged_variable.id=18;ranged_variable.function_entry=entry;ranged_variable.name="ranged_value";
                ranged_variable.location_ranges={database::DebugLocationRange{0x1000,0x1004,{0x50},{{static_cast<std::uint8_t>(symbols::LocationOperationKind::register_location),0,0,0,0}}},database::DebugLocationRange{0x1004,0x1008,{0x51},{{static_cast<std::uint8_t>(symbols::LocationOperationKind::register_location),1,0,0,0}}}};
                user->debug_variables.push_back(ranged_variable);
                type_symbols->update(project, Location{Address{{0},0x1002}}, {});
                auto *debug_variables = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("debug-variables", type_symbols));
                if (!debug_variables || debug_variables->GetItemCount() != 2 ||
                    !debug_variables->GetItemText(0, 5).Contains("CFA-0x10"))
                    throw std::runtime_error("DWARF CFA-relative offset was not shown in the Variables table");
                debug_variables->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                auto *debug_details = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("debug-variable-details", type_symbols));
                auto *go_to_variable_function = dynamic_cast<wxButton *>(
                    wxWindow::FindWindowByName("debug-variable-go-to-function", type_symbols));
                std::optional<Location> variable_navigation;
                type_symbols->navigate = [&](Location location) { variable_navigation = location; };
                if (!go_to_variable_function || go_to_variable_function->IsEnabled())
                    throw std::runtime_error("DWARF function navigation should be disabled until a variable is selected");
                if (!debug_details || !debug_details->GetValue().Contains("CFA-0x10") ||
                    !debug_details->GetValue().Contains("not an absolute address"))
                    throw std::runtime_error("DWARF variable details omitted the bounded CFA-relative location");
                debug_variables->SetItemState(1, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                if (!go_to_variable_function->IsEnabled())
                    throw std::runtime_error("Selected DWARF variable did not enable owning-function navigation");
                wxCommandEvent go_to_function_event(wxEVT_BUTTON, go_to_variable_function->GetId());
                go_to_variable_function->GetEventHandler()->ProcessEvent(go_to_function_event);
                if (variable_navigation != Location{entry})
                    throw std::runtime_error("DWARF variable did not navigate to its owning function entry");
                if(!debug_variables->GetItemText(1,5).Contains("DW_OP_reg0") || !debug_details->GetValue().Contains("[0x1000, 0x1004)") || !debug_details->GetValue().Contains("active at selected PC"))
                    throw std::runtime_error("DWARF location-list view did not select the active PC range");
                type_symbols->update(project, Location{Address{{0},0x1006}}, {});
                debug_variables = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("debug-variables", type_symbols));
                if(!debug_variables || !debug_variables->GetItemText(1,5).Contains("DW_OP_reg1"))
                    throw std::runtime_error("DWARF location-list table did not follow the selected PC to its second range");
                debug_variables->SetItemState(1, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                if(!debug_details->GetValue().Contains("[0x1004, 0x1008)") || !debug_details->GetValue().Contains("active at selected PC"))
                    throw std::runtime_error("DWARF location-list details did not show the second active PC range");
                type_symbols->update(project, Location{Address{{0},0x1008}}, {});
                debug_variables = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("debug-variables", type_symbols));
                if(!debug_variables || !debug_variables->GetItemText(1,5).Contains("no location at selected PC"))
                    throw std::runtime_error("DWARF location-list view treated an exclusive end address as covered");
                type_symbols->update(project, std::nullopt, {});
                debug_variables = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("debug-variables", type_symbols));
                if(!debug_variables || !debug_variables->GetItemText(1,5).Contains("2 PC ranges"))
                    throw std::runtime_error("DWARF location-list view did not list ranges when no PC is selected");
                std::vector<ProjectCommand> edits;

                view->update(&snapshot, Address{{0}, 0x1001}, nullptr, project.get(),
                             [&](ProjectCommand command) { edits.push_back(std::move(command)); });
                auto *addresses = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("pseudocode-addresses", view));
                auto *source = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("pseudocode-source", view));
                auto *status = wxWindow::FindWindowByName("pseudocode-status", view);
                auto *variables = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("pseudocode-variables", view));
                if (!addresses || !source || !status || addresses->GetItemCount() != 2 ||
                    addresses->GetItemText(0, 0) != "0x1000" || addresses->GetItemText(1, 0) != "0x1002" ||
                    !source->GetValue().Contains("calculate /* u64 */ =") || !source->GetValue().Contains("return;") ||
                    !status->GetLabel().Contains("0x1000") || !status->GetLabel().Contains("calculate") ||
                    addresses->GetItemText(0, 1) != "updates accumulator calculate:")
                    throw std::runtime_error("Recovered function was not lifted, SSA-rendered, and address synchronized");
                if (!variables || variables->GetItemCount() != 1 || variables->GetItemText(0, 0) != "calculate" ||
                    variables->GetItemText(0, 1) != "u64" || variables->GetItemText(0, 2) != "0x1000")
                    throw std::runtime_error("Pseudocode variable definitions were not presented with type and origin");
                if (!source->GetValue().Contains("calculate /* u64 */ ="))
                    throw std::runtime_error("Pseudocode did not resolve a uniquely defined variable's saved name and type");
                DocumentSnapshot document;
                document.project = project;
                ListingRow listing_row;
                listing_row.location = entry;
                listing_row.instruction = add;
                const auto listing = listing_text(document, listing_row);
                if (!listing.Contains("calculate") || !listing.Contains("updates accumulator"))
                    throw std::runtime_error("Pseudocode annotations did not synchronize into disassembly text");

                view->prompt = [](const wxString &title, const wxString &, bool) -> std::optional<wxString> {
                    if (title == "Rename function") return "calculate_total";
                    if (title == "Comment instruction") return "updates total";
                    if (title == "Rename local") return "total";
                    if (title == "Rename pseudocode variable") return "accumulator";
                    if (title == "Assign pseudocode variable type") return "u32";
                    return {};
                };
                auto *rename_variable = dynamic_cast<wxButton *>(wxWindow::FindWindowByName("pseudocode-rename-variable", view));
                auto *assign_type = dynamic_cast<wxButton *>(wxWindow::FindWindowByName("pseudocode-assign-type", view));
                if (!rename_variable || !assign_type) throw std::runtime_error("Pseudocode variable edit actions are missing");
                const auto variable_position = source->GetValue().Find("calculate /*");
                if (variable_position == wxNOT_FOUND) throw std::runtime_error("Renamed SSA variable is not visible in pseudocode");
                source->SetSelection(variable_position, variable_position + 9);
                wxCommandEvent variable_event(wxEVT_BUTTON, rename_variable->GetId());
                rename_variable->GetEventHandler()->ProcessEvent(variable_event);
                if (edits.size() != 1 || !std::holds_alternative<Rename>(edits.back()) ||
                    std::get<Rename>(edits.back()).location != Location{entry} ||
                    std::get<Rename>(edits.back()).name != "accumulator")
                    throw std::runtime_error("Pseudocode variable rename did not resolve to its unique definition");
                source->SetSelection(variable_position, variable_position + 9);
                wxCommandEvent type_event(wxEVT_BUTTON, assign_type->GetId());
                assign_type->GetEventHandler()->ProcessEvent(type_event);
                if (edits.size() != 2 || !std::holds_alternative<AssignType>(edits.back()) ||
                    std::get<AssignType>(edits.back()).location != entry ||
                    std::get<AssignType>(edits.back()).type_id != 9)
                    throw std::runtime_error("Pseudocode variable type did not submit an address-bound assignment command");
                auto *rename_function = dynamic_cast<wxButton *>(wxWindow::FindWindowByName("pseudocode-rename-function", view));
                if (!rename_function) throw std::runtime_error("Function rename action is missing");
                wxCommandEvent rename_event(wxEVT_BUTTON, rename_function->GetId());
                rename_function->GetEventHandler()->ProcessEvent(rename_event);
                if (edits.size() != 3 || !std::holds_alternative<Rename>(edits.back()) ||
                    std::get<Rename>(edits.back()).location != Location{entry} ||
                    std::get<Rename>(edits.back()).name != "calculate_total")
                    throw std::runtime_error("Function edit did not submit a workspace rename command");
                auto *edit_comment = dynamic_cast<wxButton *>(wxWindow::FindWindowByName("pseudocode-edit-comment", view));
                wxCommandEvent comment_event(wxEVT_BUTTON, edit_comment->GetId());
                edit_comment->GetEventHandler()->ProcessEvent(comment_event);
                if (edits.size() != 4 || !std::holds_alternative<Comment>(edits.back()) ||
                    std::get<Comment>(edits.back()).location != Location{entry} ||
                    std::get<Comment>(edits.back()).text != "updates total")
                    throw std::runtime_error("Instruction comment did not submit a workspace comment command");

                view->update(&snapshot, Address{{0}, 0x2008}, nullptr, project.get(),
                             [&](ProjectCommand command) { edits.push_back(std::move(command)); });
                bool recovered_local_present = false;
                if (variables) for (long row = 0; row < variables->GetItemCount(); ++row)
                    recovered_local_present = recovered_local_present ||
                        (variables->GetItemText(row, 0) == "counter" &&
                         variables->GetItemText(row, 1) == "u32" &&
                         variables->GetItemText(row, 2) == "0x2008");
                if (!recovered_local_present)
                    throw std::runtime_error("Recovered stack local was not added to variable definitions with its width and access site");
                if (!source->GetValue().Contains("counter /* u32 */"))
                    throw std::runtime_error("Saved stack-local name and recovered type were not synchronized into pseudocode");
                auto *stack_slots = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("pseudocode-stack-slots", view));
                if (!stack_slots || stack_slots->GetItemCount() != 1 ||
                    stack_slots->GetItemText(0, 0) != "-0x10" || stack_slots->GetItemText(0, 1) != "32" ||
                    stack_slots->GetItemText(0, 4) != "counter")
                    throw std::runtime_error("Pseudocode view did not show the recovered local stack slot");
                stack_slots->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                auto *rename_local = dynamic_cast<wxButton *>(wxWindow::FindWindowByName("pseudocode-rename-local", view));
                wxCommandEvent local_event(wxEVT_BUTTON, rename_local->GetId());
                rename_local->GetEventHandler()->ProcessEvent(local_event);
                if (edits.size() != 5 || !std::holds_alternative<Rename>(edits.back()) ||
                    std::get<Rename>(edits.back()).location != Location{Address{{0}, 0x2008}} ||
                    std::get<Rename>(edits.back()).name != "total")
                    throw std::runtime_error("Local edit did not submit a workspace rename at its stack access site");

                view->update(&snapshot, Address{{0}, 0x1001}, nullptr);

                std::optional<Location> navigated;
                view->navigate = [&](Location location) { navigated = location; };
                addresses->SetItemState(1, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                if (navigated != Location{Address{{0}, 0x1002}})
                    throw std::runtime_error("Pseudocode instruction row did not navigate to its origin address");

                variables->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                if (navigated != Location{entry})
                    throw std::runtime_error("Pseudocode variable row did not navigate to its definition address");

                view->update(&snapshot, Address{{0}, 0x1002}, nullptr);
                if ((addresses->GetItemState(1, wxLIST_STATE_SELECTED) & wxLIST_STATE_SELECTED) == 0)
                    throw std::runtime_error("Pseudocode selection did not follow the workspace address");
                view->update(&snapshot, mask_entry, nullptr);
                if (!source->GetValue().Contains("& 0x3f"))
                    throw std::runtime_error("Pseudocode pipeline did not recover a multi-instruction shift-pair mask");
                result_ = 0;
            } catch (const std::exception &error) {
                std::fprintf(stderr, "%s\n", error.what());
            }
            frame->Close();
        });
        return true;
    }
    int OnRun() override {
        wxApp::OnRun();
        return result_;
    }
};
} // namespace

wxIMPLEMENT_APP(PseudocodeApp);
