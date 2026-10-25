#include "hexlab/database/transaction.hpp"
#include "testing.hpp"
#include "support/checks.hpp"
#include <iostream>
using namespace hexlab;
using namespace hexlab::database;
using namespace hexlab_test;
int wmain(int argc,wchar_t** argv){
    if(argc!=4)return 2;
    const std::wstring mode=argv[1],argument=argv[3];const std::filesystem::path path=argv[2];
    return run([&]{
        if(mode==L"--write"){
            auto store=ProjectStore::create(path,{}).value();
            auto phase=testing::TransactionPhase::before_write;
            if(argument==L"during")phase=testing::TransactionPhase::during_commit;
            else if(argument==L"after")phase=testing::TransactionPhase::after_commit;
            else if(argument!=L"before")throw std::runtime_error("Unknown checkpoint");
            testing::set_transaction_callback([phase](auto actual){if(actual==phase){std::cout<<"CHECKPOINT"<<std::endl;std::string release;std::getline(std::cin,release);}});
            StateDelta delta{{AnnotationChange{{},Annotation{1,Address{{0},0x1000},"committed","durable"}}}};
            check(bool(store->commit(0,delta,1,{})),"child command commits when allowed to continue");
        }else if(mode==L"--verify"){
            const bool committed=argument==L"1";auto store=ProjectStore::open(path,ProjectMode::read_write,{}).value();auto snapshot=store->snapshot().value();
            check(snapshot->revisions.edit==(committed?1:0) && snapshot->history_cursor==(committed?1:0),"only durable revision and history cursor recovered");
            check(snapshot->user->annotations.size()==(committed?1:0),"no partially committed annotations recovered");
            if(committed){check(snapshot->user->annotations[0].name=="committed" && snapshot->user->annotations[0].comment=="durable","literal committed values recovered");check(bool(store->undo(1,{})) && store->snapshot().value()->user->annotations.empty(),"recovered inverse history is usable");check(bool(store->redo(2,{})) && store->snapshot().value()->user->annotations[0].name=="committed","recovered forward history is usable");}
        }else throw std::runtime_error("Unknown helper mode");
    });
}
