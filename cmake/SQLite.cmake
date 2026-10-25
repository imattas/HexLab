add_library(hexlab_sqlite3 SHARED "${PROJECT_SOURCE_DIR}/third_party/sqlite/sqlite3.c")
target_include_directories(hexlab_sqlite3 PUBLIC "${PROJECT_SOURCE_DIR}/third_party/sqlite")
target_compile_definitions(hexlab_sqlite3 PRIVATE SQLITE_THREADSAFE=1 SQLITE_OMIT_LOAD_EXTENSION
  SQLITE_DQS=0 SQLITE_DEFAULT_FOREIGN_KEYS=1 SQLITE_TRUSTED_SCHEMA=0)
if(WIN32)
  target_compile_definitions(hexlab_sqlite3 PRIVATE "SQLITE_API=__declspec(dllexport)")
endif()
if(APPLE)
  set_target_properties(hexlab_sqlite3 PROPERTIES INSTALL_RPATH "@loader_path")
elseif(UNIX)
  set_target_properties(hexlab_sqlite3 PROPERTIES INSTALL_RPATH "$ORIGIN")
endif()
install(TARGETS hexlab_sqlite3 RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES "${PROJECT_SOURCE_DIR}/third_party/sqlite/NOTICE" "${PROJECT_SOURCE_DIR}/third_party/sqlite/provenance.json"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/licenses/sqlite")
