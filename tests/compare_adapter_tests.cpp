#include "compare_adapter.hpp"
#include <iostream>
#include <stdexcept>

int main() {
    using namespace hexlab;
    using namespace hexlab::desktop;
    FunctionSnapshot snapshot;
    snapshot.functions = {
        std::make_shared<FunctionRecord>(FunctionRecord{FunctionId{1}, Address{{2}, 0x1000}}),
        std::make_shared<FunctionRecord>(FunctionRecord{FunctionId{2}, Address{{2}, 0x2000}}),
        std::make_shared<FunctionRecord>(FunctionRecord{FunctionId{3}, Address{{7}, 0x2000}}),
        std::make_shared<FunctionRecord>(FunctionRecord{FunctionId{4}, Address{{2}, 0x3000}})};
    snapshot.calls = {
        {FunctionId{1}, Address{{2}, 0x1010}, Address{{2}, 0x2000}, FunctionId{2}},
        {FunctionId{1}, Address{{2}, 0x1020}, Address{{2}, 0x2000}, FunctionId{2}}, // duplicate call sites
        {FunctionId{1}, Address{{2}, 0x1030}, Address{{7}, 0x2000}, FunctionId{3}},
        {FunctionId{1}, Address{{2}, 0x1040}, {}, {}}, // indirect or unresolved
        {FunctionId{4}, Address{{2}, 0x3010}, Address{{2}, 0x9999}, {}}}; // external target
    std::vector<compare::FunctionFeature> features{
        {.entry = 0x1000, .address_space = 2}, {.entry = 0x2000, .address_space = 2},
        {.entry = 0x2000, .address_space = 7}, {.entry = 0x3000, .address_space = 2}};
    populate_direct_call_neighborhoods(snapshot, features);
    if (features[0].direct_calls != std::vector<compare::FunctionAddress>{{0x2000, 2}, {0x2000, 7}} ||
        !features[1].direct_calls.empty() || !features[2].direct_calls.empty() ||
        !features[3].direct_calls.empty())
        throw std::runtime_error("comparison adapter must attach distinct, resolved, address-space-qualified callees to their owners");
    std::cout << "comparison adapter tests passed\n";
}
