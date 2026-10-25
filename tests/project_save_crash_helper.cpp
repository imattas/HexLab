#include "hexlab/database/backup.hpp"
#include "hexlab/database/transaction.hpp"
#include "testing.hpp"
#include "support/checks.hpp"
#include <iostream>
using namespace hexlab;
using namespace hexlab::database;
using namespace hexlab_test;
int wmain(int argc,wchar_t** argv){
    if(argc!=4)return 2;const std::wstring mode=argv[1],argument=argv[3];const std::filesystem::path path=argv[2];
    return run([&]{
        if(mode==L"--baseline" || mode==L"--save"){
            auto source=path;if(mode==L"--save")source+=L"-source.hxproj";
            auto store=ProjectStore::create(source,{}).value();const std::string name=mode==L"--baseline"?"baseline":"replacement";
            StateDelta delta{{AnnotationChange{{},Annotation{1,Address{{0},0x1000},name,"durable"}}}};check(bool(store->commit(0,delta,0,{})),"save fixture initialized");
            if(mode==L"--save"){
                auto phase=testing::BackupPhase::before_publish;if(argument==L"copied")phase=testing::BackupPhase::copied;else if(argument==L"after")phase=testing::BackupPhase::after_publish;else if(argument!=L"before")throw std::runtime_error("Unknown save checkpoint");
                testing::set_backup_callback([phase](auto actual,const auto&){if(actual==phase){std::cout<<"CHECKPOINT"<<std::endl;std::string release;std::getline(std::cin,release);}});
                check(bool(store->save_as(path,ReplacePolicy::replace_existing,{})),"save commits when allowed to continue");
            }
        }else if(mode==L"--verify"){
            auto store=ProjectStore::open(path,ProjectMode::read_only,{}).value();auto state=store->snapshot().value();const auto name=argument==L"baseline"?"baseline":"replacement";
            check(state->revisions.edit==1 && state->history_cursor==1 && state->user->annotations.size()==1 && state->user->annotations[0].name==name && state->user->annotations[0].comment=="durable","published destination is exactly old or complete new state");
        }else if(mode==L"--lease-owner"){
            auto store=ProjectStore::create(path,{}).value();std::cout<<"CHECKPOINT"<<std::endl;std::string release;std::getline(std::cin,release);
        }else if(mode==L"--lease-check"){
            auto store=ProjectStore::open(path,ProjectMode::read_write,{}).value();check(store->mode()==(argument==L"readonly"?ProjectMode::read_only:ProjectMode::read_write),"process lease controls editable ownership and recovers after death");
        }else throw std::runtime_error("Unknown save helper mode");
    });
}
