#pragma once

#include <optional>
#include <string>

namespace hexlab::debugger {
// A change to the remote server's default launch environment. An absent value
// removes the variable; an empty string sets it to an empty value. Names are
// case-sensitive target bytes, not expanded or inherited from the local host.
struct RemoteEnvironmentChange {
    std::string name;
    std::optional<std::string> value;
    bool operator==(const RemoteEnvironmentChange &) const = default;
};
}
