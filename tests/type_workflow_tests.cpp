#include "type_workflow.hpp"

int main() {
    using namespace hexlab;
    using namespace hexlab::desktop;
    const Address target{AddressSpaceId{7}, 0x1234};

    const auto missing_address = resolve_type_assignment_intent({}, 44);
    if (missing_address.kind != TypeAssignmentIntent::Kind::unavailable) return 1;

    const auto no_type_selected = resolve_type_assignment_intent(target, {});
    if (no_type_selected.kind != TypeAssignmentIntent::Kind::choose_type ||
        no_type_selected.address != target) return 2;

    const auto selected = resolve_type_assignment_intent(target, 44);
    if (selected.kind != TypeAssignmentIntent::Kind::assign_selected ||
        selected.address != target || selected.type_id != 44) return 3;

    const auto invalid_id = resolve_type_assignment_intent(target, 0);
    if (invalid_id.kind != TypeAssignmentIntent::Kind::choose_type) return 4;
}
