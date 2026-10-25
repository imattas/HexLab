if(WIN32)
  set(HEXLAB_DATABASE_NATIVE src/native_files_win.cpp src/lease_win.cpp)
else()
  set(HEXLAB_DATABASE_NATIVE src/native_files_posix.cpp src/lease_posix.cpp)
endif()
hexlab_add_library(database SOURCES src/connection.cpp src/codec.cpp src/schema.cpp src/project_state.cpp
  src/transaction.cpp src/history.cpp src/user_rows.cpp src/collaboration.cpp
  src/input.cpp src/backup.cpp ${HEXLAB_DATABASE_NATIVE}
  src/cache.cpp src/derived_cache.cpp
  DEPENDS hexlab::core hexlab::loaders hexlab::analysis hexlab::types)
target_link_libraries(hexlab_database PRIVATE hexlab_sqlite3)
if(BUILD_TESTING)
  target_sources(hexlab_database PRIVATE src/testing.cpp)
  target_compile_definitions(hexlab_database PRIVATE HEXLAB_DATABASE_TESTING)
endif()
if(WIN32)
  target_link_libraries(hexlab_database PRIVATE bcrypt)
endif()
