#include "main_frame.hpp"
#include "support/desktop_test_window.hpp"
#include "open_dialogs.hpp"
#include "support/fixture_files.hpp"
#include "support/pe_fixture.hpp"
#include <wx/app.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/textctrl.h>
#include <wx/dialog.h>
#include <wx/choice.h>
#include <wx/aui/floatpane.h>
#include <wx/listctrl.h>
#include <wx/timer.h>
#include <wx/log.h>
#include <wx/msw/wrapwin.h>
#include <future>
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstdlib>
using hexlab_test::FixtureFile;
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab::desktop;

class BinaryApp final:public wxApp {
    wxTimer timer_{this};
    hexlab::desktop::MainFrame* frame_=nullptr;
    std::unique_ptr<FixtureFile> file_;
    std::unique_ptr<FixtureFile> branch_,empty_,large_;
    std::unique_ptr<FixtureFile> unsupported_;
    int ticks_=0,phase_=0,result_=1;
public:
    bool OnInit() override {
        wxSetAssertHandler([](const wxString&,int,const wxString&,const wxString&,const wxString& msg){std::fprintf(stderr,"wx assertion: %s\n",msg.utf8_str().data());std::_Exit(4);});
        auto data=pe_bound_import_fixture();put_text(data,0x300,"KnownString");file_=std::make_unique<FixtureFile>(data);
        auto branch=pe_fixture();put(branch,0x200,0x74,1);put(branch,0x201,3,1);put(branch,0x202,0x90,1);put(branch,0x203,0xeb,1);put(branch,0x204,1,1);put(branch,0x205,0x90,1);put(branch,0x206,0xc3,1);branch_=std::make_unique<FixtureFile>(branch);
        empty_=std::make_unique<FixtureFile>(std::vector<std::byte>{});large_=std::make_unique<FixtureFile>(std::vector<std::byte>(1024*1024,std::byte{0x90}));
        auto unknown=pe_fixture();put(unknown,0x200,0xc5,1);unsupported_=std::make_unique<FixtureFile>(unknown);
        frame_=new hexlab::desktop::MainFrame;show_test_window(frame_);
        hexlab::OpenRequest request;request.path=file_->path;request.format=hexlab::Format::raw;
        request.format=Format::automatic;
        frame_->OpenDocument(request);
        Bind(wxEVT_TIMER,[this](wxTimerEvent&){tick();});timer_.Start(20);return true;
    }
    void fail(const char* detail){auto* output=dynamic_cast<wxTextCtrl*>(wxWindow::FindWindowByName("output",frame_));std::fprintf(stderr,"%s\nOutput: %s\n",detail,output->GetValue().utf8_str().data());timer_.Stop();frame_->Close();}
    void command(int id){wxCommandEvent event(wxEVT_MENU,id);if(!frame_->GetEventHandler()->ProcessEvent(event))std::fprintf(stderr,"Unhandled command %d\n",id);}
    bool selected(Location location){return frame_->documents().selection()==location;}
    void jump(const wxString& value,int mode){
        timer_.Stop();CallAfter([this,value,mode]{
            auto* dialog=dynamic_cast<wxDialog*>(wxWindow::FindWindowByLabel("Jump to location"));
            if(!dialog){std::fprintf(stderr,"Jump dialog missing\n");std::_Exit(3);}
            auto* entry=dynamic_cast<wxTextCtrl*>(wxWindow::FindWindowByName("location-value",dialog));
            auto* choice=dynamic_cast<wxChoice*>(wxWindow::FindWindowByName("location-mode",dialog));
            if(!entry || !choice)std::_Exit(3);entry->SetValue(value);choice->SetSelection(mode);
            wxCommandEvent ok(wxEVT_BUTTON,wxID_OK);dialog->GetEventHandler()->ProcessEvent(ok);
        });command(jump_id);timer_.Start(20);
    }
    bool clipboard(const wxString& expected){
        // OLE clipboard reads can temporarily fail after a successful flush.
        // Keep real contents checks strict; only retry unavailable reads, bounded.
        wxLogNull quiet;wxTextDataObject value;
        for(int attempt=0;attempt<20;++attempt){
            if(wxTheClipboard->Open()){
                const bool readable=wxTheClipboard->GetData(value);wxTheClipboard->Close();
                if(readable){if(value.GetText()!=expected)std::fprintf(stderr,"Clipboard got '%s', expected '%s'\n",value.GetText().utf8_str().data(),expected.utf8_str().data());return value.GetText()==expected;}
            }
            wxMilliSleep(10);
        }
        std::fprintf(stderr,"Clipboard unavailable after 200 ms, expected '%s'\n",expected.utf8_str().data());return false;
    }
    void tick(){
        if(++ticks_>500){fail("Desktop analysis timed out");return;}
        if(frame_->documents().opening())return;
        if(phase_==0){
            auto doc=frame_->documents().current();if(!doc){fail("Document not loaded");return;}
            auto* listing=dynamic_cast<wxListCtrl*>(wxWindow::FindWindowByName("disassembly",frame_));
            auto* bytes=dynamic_cast<wxListCtrl*>(wxWindow::FindWindowByName("bytes",frame_));
            auto* pe_directories=dynamic_cast<wxListCtrl*>(wxWindow::FindWindowByName("pe-directories",frame_));
            auto* pe_bound=dynamic_cast<wxListCtrl*>(wxWindow::FindWindowByName("pe-bound-imports",frame_));
            if(!listing || !bytes || listing->GetItemCount()<2 || bytes->GetItemCount()<1){fail("Real data views missing");return;}
            if(!pe_directories || !pe_bound || pe_directories->GetItemCount()<12 || pe_bound->GetItemCount()!=2 ||
               pe_bound->GetItemText(0,1)!="fixture.dll" || pe_bound->GetItemText(1,1).Find("fwd.dll")==wxNOT_FOUND ||
               pe_bound->GetItemText(1,0)!="file:0x708") {fail("PE data-directory or bound-forwarder inspection rows mismatch");return;}
            if(!selected(Address{{0},0x140001000ULL}) || doc->image->to_file_offset(Address{{0},0x140001000ULL}).value()!=FileOffset{0x200} || listing->GetItemText(0,1)!="90" || listing->GetItemText(1,1)!="C3"){fail("PE entry rendering mismatch");return;}
            command(copy_bytes_id);if(!clipboard("90")){fail("Copy Bytes mismatch");return;}
            command(copy_text_id);if(!clipboard("nop")){fail("Copy Text mismatch");return;}
            listing->SetItemState(1,wxLIST_STATE_SELECTED|wxLIST_STATE_FOCUSED,wxLIST_STATE_SELECTED|wxLIST_STATE_FOCUSED);
            if(!selected(Address{{0},0x140001001ULL}) || bytes->GetItemText(0,1).Left(2)!="C3"){fail("Single-click instruction selection did not synchronize location and bytes");return;}
            timer_.Stop();
            {
                // Deterministic contention: the clipboard still contains the
                // checked NOP while a native owner briefly holds its mutex.
                wxLogNull quiet;std::promise<bool> acquired;auto ready=acquired.get_future();
                std::jthread holder([&]{bool opened=false;for(int attempt=0;attempt<20 && !opened;++attempt){opened=::OpenClipboard(nullptr)!=0;if(!opened)std::this_thread::sleep_for(std::chrono::milliseconds(10));}acquired.set_value(opened);if(opened){std::this_thread::sleep_for(std::chrono::milliseconds(100));::CloseClipboard();}});
                if(!ready.get()){holder.join();fail("Native contention fixture could not acquire clipboard");return;}
                command(copy_text_id);holder.join();if(!clipboard("ret")){fail("Copy failed under bounded clipboard contention");return;}
            }
            timer_.Start(20);
            command(copy_bytes_id);if(!clipboard("C3")){fail("Copy ignored selected RET bytes");return;}
            command(copy_address_id);if(!clipboard("0x140001001")){fail("Copy ignored selected RET address");return;}
            bytes->SetItemState(1,wxLIST_STATE_SELECTED,wxLIST_STATE_SELECTED);
            if(!selected(Address{{0},0x140001009ULL})){fail("Single-click bytes selection did not synchronize location");return;}
            frame_->Navigate(Address{{0},0x140001000ULL});
            timer_.Stop();OpenRequest raw_request;
            CallAfter([]{
                auto* dialog=dynamic_cast<wxDialog*>(wxWindow::FindWindowByLabel("Open raw binary"));
                if(!dialog)std::_Exit(3);
                auto* base=dynamic_cast<wxTextCtrl*>(wxWindow::FindWindowByName("raw-base",dialog));
                auto* entry=dynamic_cast<wxTextCtrl*>(wxWindow::FindWindowByName("raw-entry",dialog));
                auto* error=wxWindow::FindWindowByName("raw-error",dialog);
                if(!base || !entry || !error)std::_Exit(3);
                base->SetValue("0x10000000000000000");wxCommandEvent ok(wxEVT_BUTTON,wxID_OK);dialog->GetEventHandler()->ProcessEvent(ok);
                if(!dialog->IsShown() || error->GetLabel().empty())std::_Exit(3);
                base->SetValue("0x1000");entry->SetValue("nope");dialog->GetEventHandler()->ProcessEvent(ok);
                if(!dialog->IsShown())std::_Exit(3);
                entry->SetValue("0x1001");dialog->GetEventHandler()->ProcessEvent(ok);
            });
            if(!configure_raw_mapping(frame_,raw_request) || !raw_request.raw || raw_request.raw->base.offset!=0x1000 || raw_request.raw->entry!=Address{{0},0x1001}){fail("Raw dialog validation failed");return;}timer_.Start(20);
            jump("0x200",1);if(!selected(FileOffset{0x200})){fail("File-offset jump failed");return;}
            jump("0x140001000",0);if(!selected(Address{{0},0x140001000ULL})){fail("Virtual jump failed");return;}
            jump("0xnope",0);if(!selected(Address{{0},0x140001000ULL})){fail("Invalid numeric jump changed selection");return;}
            frame_->Navigate(Address{{0},0x140001800ULL});if(!selected(Address{{0},0x140001000ULL})){fail("Invalid jump changed selection");return;}
            auto* strings=dynamic_cast<wxListCtrl*>(wxWindow::FindWindowByName("strings",frame_));
            long index=-1;for(long i=0;i<strings->GetItemCount();++i)if(strings->GetItemText(i,1)=="KnownString"){index=i;break;}
            if(index<0){fail("Known string missing");return;}strings->SetItemState(index,wxLIST_STATE_SELECTED,wxLIST_STATE_SELECTED);
            if(!selected(Address{{0},0x140001100ULL}) || bytes->GetItemText(0,1).Left(5)!="4B 6E"){fail("String selection did not synchronize bytes");return;}
            OpenRequest request;request.path=branch_->path;frame_->OpenDocument(request);phase_=1;
        }else if(phase_==1){
            command(follow_id);if(!selected(Address{{0},0x140001005ULL})){fail("Follow direct branch failed");return;}
            command(back_id);if(!selected(Address{{0},0x140001000ULL})){fail("Back failed");return;}
            command(forward_id);if(!selected(Address{{0},0x140001005ULL})){fail("Forward failed");return;}
            command(copy_address_id);if(!clipboard("0x140001005")){fail("Copy Address failed");return;}
            frame_->Navigate(Address{{0},0x140001000ULL});
            auto* listing=dynamic_cast<wxListCtrl*>(wxWindow::FindWindowByName("disassembly",frame_));listing->SetItemState(2,wxLIST_STATE_SELECTED,wxLIST_STATE_SELECTED);
            if(!selected(Address{{0},0x140001003ULL})){fail("Nonfirst branch selection failed");return;}
            command(follow_id);if(!selected(Address{{0},0x140001006ULL})){fail("Follow ignored nonfirst branch row");return;}
            command(back_id);if(!selected(Address{{0},0x140001003ULL})){fail("Selected branch history failed");return;}
            frame_->Navigate(Address{{0},0x140001005ULL});
            OpenRequest bad;bad.path=L"missing-desktop-fixture.exe";frame_->OpenDocument(bad);phase_=2;
        }else if(phase_==2){
            auto* output=dynamic_cast<wxTextCtrl*>(wxWindow::FindWindowByName("output",frame_));
            if(!frame_->documents().current() || !frame_->documents().last_error() || !selected(Address{{0},0x140001005ULL}) || output->GetValue().empty()){fail("Failed open damaged document or diagnostic");return;}
            OpenRequest request;request.path=large_->path;request.format=Format::raw;request.raw=RawOptions{Architecture::x86_64,ExecutionMode::x86_64,{{0},0x1000},true,false,true,{}};
            frame_->OpenDocument(request);command(cancel_id);if(frame_->documents().opening() || !selected(Address{{0},0x140001005ULL})){fail("Cancel damaged document");return;}
            frame_->OpenDocument(request);request.path=empty_->path;frame_->OpenDocument(request);phase_=3;
        }else if(phase_==3){
            if(!frame_->documents().current() || frame_->documents().current()->image->storage()->size()!=0 || frame_->documents().selection()){fail("Latest empty raw open failed");return;}
            auto closed=frame_->projects().active_document();command(wxID_CLOSE);if(closed && (frame_->projects().actor(*closed) || frame_->projects().active_document()==closed)){fail("Close did not release active document");return;}frame_->CloseAllDocuments();if(frame_->documents().current()){fail("Close all retained a document");return;}
            OpenRequest request;request.path=unsupported_->path;frame_->OpenDocument(request);phase_=4;
        }else{
            auto* output=dynamic_cast<wxTextCtrl*>(wxWindow::FindWindowByName("output",frame_));
            if(!output->GetValue().Contains("0x140001000"))return;
            frame_->SetClientSize(900,650);frame_->SendSizeEvent();
            if(wxAuiManager::GetManager(frame_)->GetPane("metadata").dock_direction!=wxAUI_DOCK_BOTTOM){fail("Compact window did not preserve listing width");return;}
            auto* manager=wxAuiManager::GetManager(frame_);auto& pane=manager->GetPane("functions");pane.Float();manager->Update();if(!pane.frame || !pane.frame->Close()){fail("Active document floating close failed");return;}frame_->ResetLayout();pane.Float();manager->Update();
            OpenRequest request;request.path=large_->path;request.format=Format::raw;request.raw=RawOptions{Architecture::x86_64,ExecutionMode::x86_64,{{0},0x1000},true,false,true,{}};frame_->OpenDocument(request);
            result_=0;timer_.Stop();frame_->Close();
        }
    }
    int OnRun() override{wxApp::OnRun();return result_;}
};
wxIMPLEMENT_APP(BinaryApp);
