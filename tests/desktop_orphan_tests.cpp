#include "main_frame.hpp"
#include "support/desktop_test_window.hpp"
#include "project_actions.hpp"
#include "support/fixture_files.hpp"
#include "support/pe_fixture.hpp"
#include <wx/app.h>
#include <wx/dialog.h>
#include <wx/textctrl.h>
#include <wx/listctrl.h>
#include <wx/timer.h>
#include <cstdio>
using namespace hexlab;using namespace hexlab::desktop;using namespace hexlab_test;
namespace {
class OrphanApp final:public wxApp {
    wxTimer timer_{this};MainFrame* frame=nullptr;std::unique_ptr<FixtureFile> input;std::filesystem::path path;int phase=0,ticks=0,result=1;const Address entry{{0},0x140001000};
public:
    bool OnInit()override{wxSetAssertHandler([](const wxString&,int,const wxString&,const wxString&,const wxString& message){std::fprintf(stderr,"wx assertion: %s\n",message.utf8_str().data());std::_Exit(4);});input=std::make_unique<FixtureFile>(pe_fixture());path=input->path.wstring()+L".orphan.hxproj";frame=new MainFrame;show_test_window(frame);OpenRequest request;request.path=input->path;frame->OpenDocument(request);Bind(wxEVT_TIMER,[this](wxTimerEvent&){tick();});timer_.Start(20);return true;}
    void fail(const char* message){std::fprintf(stderr,"%s (phase %d)\n",message,phase);timer_.Stop();frame->CloseAllDocuments();frame->Close();}
    void send(int id){wxCommandEvent event(wxEVT_MENU,id);frame->GetEventHandler()->ProcessEvent(event);}
    void comment(){timer_.Stop();CallAfter([]{auto* field=dynamic_cast<wxTextCtrl*>(wxWindow::FindWindowByName("edit-value"));auto* dialog=field?dynamic_cast<wxDialog*>(field->GetParent()):nullptr;if(!field || !dialog)std::_Exit(3);field->SetValue("updated orphan");wxCommandEvent okay(wxEVT_BUTTON,wxID_OK);dialog->GetEventHandler()->ProcessEvent(okay);});send(comment_id);timer_.Start(20);}
    void tick(){
        if(++ticks>1000){fail("Orphan workflow timed out");return;}if(frame->documents().opening())return;auto id=frame->projects().active_document();if(!id)return;auto snapshot=frame->projects().project(*id);if(!snapshot)return;auto revision=snapshot->state->revisions.edit;
        if(phase==0){if(!frame->SaveProjectAs(path)){fail("Cannot save orphan fixture");return;}phase=1;}
        else if(phase==1){if(!frame->projects().documents()[0].path)return;if(!frame->ApplyProjectCommand(Rename{entry,"orphan_name"}) || !frame->ApplyProjectCommand(Comment{entry,"retained"}) || !frame->ApplyProjectCommand(BookmarkCommand{entry,"address bookmark",false})){fail("Cannot queue annotation fixture");return;}phase=2;}
        else if(phase==2){if(revision!=3)return;if(!frame->ApplyProjectCommand(PatchBytes{FileOffset{0},bytes({0})})){fail("Cannot queue header patch");return;}phase=3;}
        else if(phase==3){if(revision!=4 || snapshot->status!=DerivedStatus::file_only)return;auto* annotations=dynamic_cast<wxListCtrl*>(wxWindow::FindWindowByName("annotations",frame));auto* bookmarks=dynamic_cast<wxListCtrl*>(wxWindow::FindWindowByName("bookmarks",frame));if(!annotations || annotations->GetItemCount()!=1 || annotations->GetItemText(0,1)!="orphan_name" || annotations->GetItemText(0,3)!="orphaned" || !bookmarks || bookmarks->GetItemText(0,2)!="orphaned" || !frame->documents().current()->image->layout().segments.empty()){fail("Invalid mapping did not expose retained orphan records and file-only bytes");return;}annotations->SetItemState(0,wxLIST_STATE_SELECTED,wxLIST_STATE_SELECTED);frame->UpdateWindowUI(wxUPDATE_UI_RECURSE);if(!frame->GetMenuBar()->FindItem(comment_id)->IsEnabled() || frame->GetMenuBar()->FindItem(patch_id)->IsEnabled() || frame->GetMenuBar()->FindItem(copy_bytes_id)->IsEnabled() || !frame->GetMenuBar()->FindItem(copy_address_id)->IsEnabled()){fail("Orphan context uses wrong action prerequisites");return;}comment();phase=4;}
        else if(phase==4){if(revision!=5)return;if(snapshot->state->user->annotations[0].comment!="updated orphan"){fail("Orphan comment did not commit at its logical address");return;}send(wxID_UNDO);phase=5;}
        else if(phase==5){if(revision!=6)return;send(wxID_UNDO);phase=6;}
        else{if(revision!=7 || snapshot->status==DerivedStatus::file_only)return;auto* annotations=dynamic_cast<wxListCtrl*>(wxWindow::FindWindowByName("annotations",frame));if(!snapshot->loaded || !annotations || annotations->GetItemText(0,3)!="mapped" || snapshot->state->user->annotations[0].name!="orphan_name" || snapshot->state->user->annotations[0].comment!="retained"){fail("Undo did not restore mapping and authoritative annotation");return;}result=0;timer_.Stop();frame->Close();}
    }
    int OnRun()override{wxApp::OnRun();return result;}
    int OnExit()override{std::error_code ignored;for(auto suffix:{L"",L"-wal",L"-shm"}){auto file=path;file+=suffix;std::filesystem::remove(file,ignored);}return wxApp::OnExit();}
};
}
wxIMPLEMENT_APP(OrphanApp);
