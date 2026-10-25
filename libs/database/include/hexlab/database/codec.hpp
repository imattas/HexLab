#pragma once
#include "hexlab/database/project_state.hpp"
namespace hexlab::database {
inline constexpr std::size_t project_record_limit=100000;
inline constexpr std::size_t project_payload_limit=64*1024*1024;
HEXLAB_DATABASE_EXPORT Result<std::vector<std::byte>> encode_location(Location);
HEXLAB_DATABASE_EXPORT Result<Location> decode_location(std::span<const std::byte>);
HEXLAB_DATABASE_EXPORT Result<bool> validate_user_state(const UserState&);
HEXLAB_DATABASE_EXPORT Result<std::vector<std::byte>> encode_user_state(const UserState&);
HEXLAB_DATABASE_EXPORT Result<UserState> decode_user_state(std::span<const std::byte>);
}
