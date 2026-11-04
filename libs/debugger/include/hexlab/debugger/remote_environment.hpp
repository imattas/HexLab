#pragma once

#include <optional>
#include <string>
#include <vector>

namespace hexlab::debugger {
// A launch-environment change. An absent value removes the variable; an empty
// string sets it to an empty value. Names are case-sensitive target bytes and
// values are not expanded by the debugger.
struct RemoteEnvironmentChange {
    std::string name;
    std::optional<std::string> value;
    bool operator==(const RemoteEnvironmentChange &) const = default;
};

// A complete launch-environment patch and working-directory value. An empty
// environment is the target's default-environment baseline; an empty working
// directory is the target's default directory.
struct RemoteLaunchSettings {
    std::vector<RemoteEnvironmentChange> environment;
    std::string working_directory;
    bool operator==(const RemoteLaunchSettings &) const = default;
};
}
