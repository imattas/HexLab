function(hexlab_add_library component)
  cmake_parse_arguments(HL "" "" "SOURCES;DEPENDS" ${ARGN})
  set(target "hexlab_${component}")
  add_library(${target} SHARED ${HL_SOURCES})
  add_library(hexlab::${component} ALIAS ${target})
  generate_export_header(${target} EXPORT_FILE_NAME
    "${PROJECT_BINARY_DIR}/generated/hexlab/${component}/${component}_export.hpp")
  target_include_directories(${target} PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/generated>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
  target_link_libraries(${target} PUBLIC hexlab_options ${HL_DEPENDS})
  set_target_properties(${target} PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0)
  if(APPLE)
    set_target_properties(${target} PROPERTIES INSTALL_RPATH "@loader_path")
  elseif(UNIX)
    set_target_properties(${target} PROPERTIES INSTALL_RPATH "$ORIGIN")
  endif()
  install(TARGETS ${target} RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
  install(DIRECTORY include/hexlab DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}" FILES_MATCHING PATTERN "*.hpp")
  install(FILES "${PROJECT_BINARY_DIR}/generated/hexlab/${component}/${component}_export.hpp"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/hexlab/${component}")
endfunction()
