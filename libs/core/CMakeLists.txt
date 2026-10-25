add_library(hexlab_core SHARED src/address.cpp src/byte_reader.cpp src/version.cpp src/sha256.cpp src/encoding.cpp src/x86_segments.cpp)
add_library(hexlab::core ALIAS hexlab_core)
generate_export_header(hexlab_core EXPORT_FILE_NAME
  "${PROJECT_BINARY_DIR}/generated/hexlab/core/core_export.hpp")
configure_file(include/hexlab/core/version.hpp.in
  "${PROJECT_BINARY_DIR}/generated/hexlab/core/version.hpp" @ONLY)
target_include_directories(hexlab_core PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/generated>"
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
target_link_libraries(hexlab_core PUBLIC hexlab_options)
set_target_properties(hexlab_core PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0)
install(TARGETS hexlab_core RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(DIRECTORY include/hexlab DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  FILES_MATCHING PATTERN "*.hpp")
install(FILES "${PROJECT_BINARY_DIR}/generated/hexlab/core/core_export.hpp"
  "${PROJECT_BINARY_DIR}/generated/hexlab/core/version.hpp"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/hexlab/core")
