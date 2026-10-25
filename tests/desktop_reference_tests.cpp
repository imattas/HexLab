#include "reference_view.hpp"
#include "support/desktop_test_window.hpp"
#include "hexlab/loaders/loaded_image.hpp"
#include "support/analysis_fixture.hpp"
#include <wx/app.h>
#include <wx/frame.h>
#include <wx/sizer.h>
#include <cstdio>
using namespace hexlab;
using namespace hexlab::desktop;
namespace {
class ReferenceApp final : public wxApp {
    wxFrame *frame = nullptr;
    int result = 1;

  public:
    bool OnInit() override {
        wxSetAssertHandler([](const wxString &, int, const wxString &, const wxString &, const wxString &message) {
            std::fprintf(stderr, "wx assertion: %s\n", message.utf8_str().data());
            std::_Exit(4);
        });
        frame = new wxFrame(nullptr, wxID_ANY, "Reference paging");
        auto *view = new ReferenceView(frame);
        auto *box = new wxBoxSizer(wxVERTICAL);
        box->Add(view, 1, wxEXPAND);
        frame->SetSizer(box);
        frame->SetSize(800, 450);
        show_test_window(frame);
        CallAfter([this, view] {
            auto check = [](bool condition, const char *message) {
                if (!condition)
                    throw std::runtime_error(message);
            };
            try {
                std::vector<Reference> references;
                for (std::uint64_t i = 0; i < 600; ++i)
                    references.push_back({{0},
                                          Address{{0}, 0x1000},
                                          {},
                                          Location{FileOffset{i}},
                                          ReferenceKind::user_data,
                                          OperandAccess::address,
                                          {ReferenceProvenanceKind::user, 0, i + 1},
                                          {}});
                auto index = ReferenceIndex::create(std::move(references), {}, true, {});
                if (!index)
                    throw std::runtime_error(index.error().message);
                auto expected = [&](std::size_t row) { return std::get<Location>(index.value()->all()[row].target); };
                auto expected_text = [&](std::size_t row) {
                    return wxString::Format("file:0x%llX",
                                            static_cast<unsigned long long>(std::get<FileOffset>(expected(row)).value));
                };
                auto project = std::make_shared<ProjectSnapshot>();
                project->references = index.value();
                project->status = DerivedStatus::fresh;
                view->update(DocumentId{41}, project, Address{{0}, 0x1000});
                auto *rows = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("references", view));
                auto *next = dynamic_cast<wxButton *>(wxWindow::FindWindowByName("reference-next", view));
                auto *previous = dynamic_cast<wxButton *>(wxWindow::FindWindowByName("reference-previous", view));
                check(rows && next && previous, "Native reference controls missing");
                check(rows->GetItemCount() == 256 && next->IsEnabled() && !previous->IsEnabled(),
                      "First reference page is not bounded to 256 rows");
                std::optional<std::pair<DocumentId, Location>> selected;
                view->navigate = [&](DocumentId id, Location location) { selected = std::pair{id, location}; };
                rows->SetItemState(255, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                check(selected && selected->first == DocumentId{41} && selected->second == expected(255),
                      "Nonfirst outgoing page row did not emit its canonical file offset");
                auto click = [](wxButton *button) {
                    wxCommandEvent event(wxEVT_BUTTON, button->GetId());
                    button->GetEventHandler()->ProcessEvent(event);
                };
                click(next);
                check(rows->GetItemCount() == 256 && rows->GetItemText(0, 1) == expected_text(256) &&
                          previous->IsEnabled(),
                      "Second reference page repeats or skips rows");
                click(next);
                check(rows->GetItemCount() == 88 && !next->IsEnabled() &&
                          rows->GetItemText(87, 1) == expected_text(599),
                      "Last reference page loses its exact boundary");
                click(previous);
                check(rows->GetItemText(0, 1) == expected_text(256), "Previous page lost its canonical cursor");
                view->update(DocumentId{41}, project, FileOffset{256});
                auto *direction = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("reference-direction", view));
                direction->SetSelection(1);
                wxCommandEvent change(wxEVT_CHOICE, direction->GetId());
                direction->GetEventHandler()->ProcessEvent(change);
                check(rows->GetItemCount() == 1 && rows->GetItemText(0, 0) == "0x1000",
                      "Incoming page does not query the selected file domain");
                rows->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                check(selected->second == Location{Address{{0}, 0x1000}},
                      "Incoming page did not emit the source virtual address");
                auto pending = std::make_shared<ProjectSnapshot>(*project);
                pending->status = DerivedStatus::pending;
                view->update(DocumentId{41}, pending, FileOffset{256});
                check(rows->GetItemCount() == 0 && !next->IsEnabled(),
                      "Pending facts remain navigable as current references");
                Reference relocation{
                    {0},
                    Address{{0}, 0x2000},
                    0u,
                    UnresolvedTarget{UnresolvedReason::elf_relocation, RelativeOperand{-4, 32, 64, EncodedField{1, 4}}},
                    ReferenceKind::call,
                    OperandAccess::address,
                    {ReferenceProvenanceKind::decoded, 1, 0},
                    {}};
                ElfRelocation origin;
                origin.source = {7, 1792, {}};
                origin.type = 4;
                origin.symbol_index = 2;
                origin.symbol_index_validated = true;
                origin.symbol_table = ElfTableSource{5, 1024, {}};
                origin.offset = 0x2001;
                origin.explicit_addend = true;
                origin.addend = -4;
                origin.field_size = 4;
                origin.kind = ElfRelocationKind::plt_relative;
                origin.place = Address{{0}, 0x2001};
                origin.file_place = FileOffset{1};
                origin.record_file_offset = 1792;
                origin.record_stride = 24;
                ElfSymbol symbol;
                symbol.table = 5;
                symbol.table_offset = 1024;
                symbol.index = 2;
                symbol.name_index = 8;
                symbol.name = "external";
                symbol.type = 2;
                symbol.binding = 1;
                relocation.provenance.kind = ReferenceProvenanceKind::elf_relocation;
                relocation.provenance.elf =
                    ElfReferenceProvenance{ElfResolutionReason::unsupported, {{origin, symbol}}};
                auto elf_index = ReferenceIndex::create({relocation}, {}, false, {});
                check(bool(elf_index), "Native ELF relocation reference fixture failed");
                auto elf_project = std::make_shared<ProjectSnapshot>();
                elf_project->references = elf_index.value();
                elf_project->status = DerivedStatus::incomplete;
                view->update(DocumentId{42}, elf_project, Address{{0}, 0x2000});
                check(rows->GetItemCount() == 1 && rows->GetItemText(0, 1).Contains("ELF relocation") &&
                          rows->GetItemText(0, 1).Contains("external") && rows->GetItemText(0, 3) == "ELF relocation",
                      "Unresolved ELF control reference lost its native declared symbol name or provenance label");
                selected.reset();
                rows->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                check(selected && selected->first == DocumentId{42} &&
                          selected->second == Location{Address{{0}, 0x2000}},
                      "Unresolved relocation reference did not navigate to its source for inspection");
                auto raw = relocation;
                raw.id = {0};
                raw.source = Address{{0}, 0x2001};
                raw.operand_index.reset();
                raw.provenance.instruction_id = 0;
                raw.kind = ReferenceKind::relocation;
                raw.target = UnresolvedTarget{UnresolvedReason::elf_relocation, std::monostate{}};
                auto raw_project = std::make_shared<ProjectSnapshot>();
                raw_project->references = ReferenceIndex::create({raw}, {}, false, {}).value();
                raw_project->status = DerivedStatus::incomplete;
                view->update(DocumentId{43}, raw_project, Address{{0}, 0x2001});
                check(rows->GetItemCount() == 1 && rows->GetItemText(0, 2) == "relocation" &&
                          rows->GetItemText(0, 3) == "ELF relocation",
                      "Native reference view cannot distinguish raw relocation fields from decoded memory accesses");

                const Address entry{{0}, 0x1000}, destination{{0}, 0x1010};
                auto image_storage = std::make_shared<hexlab_test::MemoryStorage>(std::vector<std::byte>(0x40));
                ImageLayout image_layout{{{0}, 64, 1, ByteOrder::little}, Architecture::x86_64,
                    ExecutionMode::x86_64,
                    {{".text", entry, 0x40, FileOffset{0}, 0x40, true, false, true}}, {entry}};
                auto image = Image::create(image_storage, std::move(image_layout)).value();
                auto loaded = std::make_shared<LoadedImage>();
                loaded->image = image;
                auto rich_project = std::make_shared<ProjectSnapshot>();
                rich_project->loaded = loaded;
                auto state = std::make_shared<database::ProjectState>();
                auto user = std::make_shared<database::UserState>();
                user->annotations = {{1, entry, "dispatch", "entry comment"},
                                     {2, destination, "payload", "target comment"}};
                state->user = user;
                rich_project->state = state;
                auto function = std::make_shared<FunctionRecord>();
                function->id = {1};
                function->entry = entry;
                function->chunks.push_back({entry, 0x20, {}});
                auto functions = std::make_shared<FunctionSnapshot>();
                functions->functions.push_back(function);
                rich_project->functions = functions;
                Reference context_reference{{0}, entry, {}, Location{destination},
                    ReferenceKind::call, OperandAccess::address,
                    {ReferenceProvenanceKind::decoded, 1, 0}, {}};
                auto context_index = ReferenceIndex::create({context_reference}, {}, true, {});
                check(bool(context_index), "Navigation context xref fixture failed");
                rich_project->references = context_index.value();
                rich_project->status = DerivedStatus::fresh;
                view->update(DocumentId{44}, rich_project, entry);
                check(rows->GetItemCount() == 1 && rows->GetColumnCount() == 7 &&
                          rows->GetItemText(0, 5).Contains("dispatch") &&
                          rows->GetItemText(0, 5).Contains("entry comment") &&
                          rows->GetItemText(0, 5).Contains(".text") &&
                          rows->GetItemText(0, 6).Contains("payload") &&
                          rows->GetItemText(0, 6).Contains("target comment") &&
                          rows->GetItemText(0, 6).Contains("dispatch+0x10") &&
                          rows->GetItemText(0, 6).Contains(".text"),
                      "Reference rows do not connect endpoint names/comments, function ownership, and segment context");
                view->navigate = {};
                result = 0;
            } catch (const std::exception &error) {
                std::fprintf(stderr, "%s\n", error.what());
            }
            frame->Close();
        });
        return true;
    }
    int OnRun() override {
        wxApp::OnRun();
        return result;
    }
};
} // namespace
wxIMPLEMENT_APP(ReferenceApp);
