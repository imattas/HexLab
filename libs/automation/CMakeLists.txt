cmake_minimum_required(VERSION 3.24)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(HexLabAutomation VERSION 0.1.0 LANGUAGES CXX)
  include(CTest)
  include(GNUInstallDirs)
  include(GenerateExportHeader)
  get_filename_component(HEXLAB_SOURCE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
  set(HEXLAB_ENGINE_BUILD "" CACHE PATH "Complete HexLab source build containing generated headers and libraries")
  set(HEXLAB_DEBUGGER_BUILD "" CACHE PATH "HexLab debugger component build containing hexlab_debugger.lib")
  if(NOT IS_DIRECTORY "${HEXLAB_ENGINE_BUILD}/generated")
    message(FATAL_ERROR "Set HEXLAB_ENGINE_BUILD to a complete HexLab build")
  endif()
  add_library(hexlab_options INTERFACE)
  target_compile_features(hexlab_options INTERFACE cxx_std_20)
  target_compile_options(hexlab_options INTERFACE
    $<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/W4;/permissive-;/utf-8>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic>)
  foreach(component core symbols firmware image loaders database processors types analysis workspace decompiler)
    add_library(hexlab_${component} SHARED IMPORTED)
    add_library(hexlab::${component} ALIAS hexlab_${component})
    set_target_properties(hexlab_${component} PROPERTIES
      MAP_IMPORTED_CONFIG_MINSIZEREL Release MAP_IMPORTED_CONFIG_RELWITHDEBINFO Release
      INTERFACE_INCLUDE_DIRECTORIES "${HEXLAB_SOURCE_ROOT}/libs/${component}/include;${HEXLAB_ENGINE_BUILD}/generated")
    foreach(config Debug Release)
      string(TOUPPER "${config}" upper)
      if(WIN32)
        set_target_properties(hexlab_${component} PROPERTIES
          IMPORTED_IMPLIB_${upper} "${HEXLAB_ENGINE_BUILD}/lib/${config}/hexlab_${component}.lib"
          IMPORTED_LOCATION_${upper} "${HEXLAB_ENGINE_BUILD}/bin/${config}/hexlab_${component}.dll")
      else()
        set_target_properties(hexlab_${component} PROPERTIES
          IMPORTED_LOCATION_${upper} "${HEXLAB_ENGINE_BUILD}/lib/libhexlab_${component}${CMAKE_SHARED_LIBRARY_SUFFIX}")
      endif()
    endforeach()
  endforeach()
  if(NOT IS_DIRECTORY "${HEXLAB_DEBUGGER_BUILD}")
    set(HEXLAB_DEBUGGER_BUILD "${HEXLAB_ENGINE_BUILD}")
  endif()
  add_library(hexlab_debugger SHARED IMPORTED)
  add_library(hexlab::debugger ALIAS hexlab_debugger)
  if(EXISTS "${HEXLAB_DEBUGGER_BUILD}/hexlab-debugger/Debug/hexlab_debugger.lib")
    set(HEXLAB_DEBUGGER_LIB_DIR "${HEXLAB_DEBUGGER_BUILD}/hexlab-debugger")
    set(HEXLAB_DEBUGGER_BIN_DIR "${HEXLAB_DEBUGGER_BUILD}/hexlab-debugger")
  else()
    set(HEXLAB_DEBUGGER_LIB_DIR "${HEXLAB_DEBUGGER_BUILD}/lib")
    set(HEXLAB_DEBUGGER_BIN_DIR "${HEXLAB_DEBUGGER_BUILD}/bin")
  endif()
  set_target_properties(hexlab_debugger PROPERTIES
    MAP_IMPORTED_CONFIG_RELEASE Debug MAP_IMPORTED_CONFIG_MINSIZEREL Debug MAP_IMPORTED_CONFIG_RELWITHDEBINFO Debug
    IMPORTED_IMPLIB_DEBUG "${HEXLAB_DEBUGGER_LIB_DIR}/Debug/hexlab_debugger.lib"
    IMPORTED_LOCATION_DEBUG "${HEXLAB_DEBUGGER_BIN_DIR}/Debug/hexlab_debugger.dll"
    IMPORTED_IMPLIB_RELEASE "${HEXLAB_DEBUGGER_LIB_DIR}/Release/hexlab_debugger.lib"
    IMPORTED_LOCATION_RELEASE "${HEXLAB_DEBUGGER_BIN_DIR}/Release/hexlab_debugger.dll"
    INTERFACE_INCLUDE_DIRECTORIES "${HEXLAB_SOURCE_ROOT}/libs/debugger/include;${HEXLAB_ENGINE_BUILD}/generated")
  include("${HEXLAB_SOURCE_ROOT}/cmake/HexLabLibrary.cmake")
endif()

option(HEXLAB_ENABLE_PYTHON_AUTOMATION "Build the trusted CPython automation script runner and console" OFF)
hexlab_add_library(automation SOURCES src/api.cpp src/history.cpp src/debug_info.cpp src/workflow_state.cpp src/annotation_import.cpp
  DEPENDS hexlab::workspace hexlab::database hexlab::analysis hexlab::loaders
          hexlab::processors hexlab::types hexlab::image hexlab::symbols hexlab::firmware hexlab::core hexlab::decompiler)

if(HEXLAB_ENABLE_PYTHON_AUTOMATION)
  find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter Development.Embed)
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/python/hexlab.py")
  file(READ "${CMAKE_CURRENT_SOURCE_DIR}/python/hexlab.py" HEXLAB_PYTHON_FACADE)
  string(FIND "${HEXLAB_PYTHON_FACADE}" ")HL_PYTHON\"" HEXLAB_PYTHON_FACADE_DELIMITER)
  if(NOT HEXLAB_PYTHON_FACADE_DELIMITER EQUAL -1)
    message(FATAL_ERROR "Python facade contains the reserved C++ raw-string delimiter")
  endif()
  # MSVC limits individual literals. Split at line endings, preserving UTF-8
  # code points and Python source exactly, rather than naming API boundaries.
  set(HEXLAB_PYTHON_FACADE_REMAINDER "${HEXLAB_PYTHON_FACADE}")
  set(HEXLAB_PYTHON_FACADE_LITERALS "")
  string(LENGTH "${HEXLAB_PYTHON_FACADE_REMAINDER}" HEXLAB_PYTHON_FACADE_LENGTH)
  while(HEXLAB_PYTHON_FACADE_LENGTH GREATER 0)
    if(HEXLAB_PYTHON_FACADE_LENGTH GREATER 12000)
      string(SUBSTRING "${HEXLAB_PYTHON_FACADE_REMAINDER}" 0 12000 HEXLAB_PYTHON_FACADE_CHUNK)
      string(FIND "${HEXLAB_PYTHON_FACADE_CHUNK}" "\n" HEXLAB_PYTHON_FACADE_LINE_END REVERSE)
      if(HEXLAB_PYTHON_FACADE_LINE_END LESS 0)
        message(FATAL_ERROR "Python facade contains a line exceeding the C++ literal budget")
      endif()
      math(EXPR HEXLAB_PYTHON_FACADE_CHUNK_LENGTH "${HEXLAB_PYTHON_FACADE_LINE_END} + 1")
    else()
      set(HEXLAB_PYTHON_FACADE_CHUNK_LENGTH ${HEXLAB_PYTHON_FACADE_LENGTH})
    endif()
    string(SUBSTRING "${HEXLAB_PYTHON_FACADE_REMAINDER}" 0 ${HEXLAB_PYTHON_FACADE_CHUNK_LENGTH} HEXLAB_PYTHON_FACADE_CHUNK)
    string(APPEND HEXLAB_PYTHON_FACADE_LITERALS "R\"HL_PYTHON(${HEXLAB_PYTHON_FACADE_CHUNK})HL_PYTHON\"\n")
    string(SUBSTRING "${HEXLAB_PYTHON_FACADE_REMAINDER}" ${HEXLAB_PYTHON_FACADE_CHUNK_LENGTH} -1 HEXLAB_PYTHON_FACADE_REMAINDER)
    string(LENGTH "${HEXLAB_PYTHON_FACADE_REMAINDER}" HEXLAB_PYTHON_FACADE_LENGTH)
  endwhile()
  configure_file(src/facade.hpp.in "${CMAKE_CURRENT_BINARY_DIR}/facade.hpp" @ONLY)
  add_executable(hexlab_python src/console.cpp src/python_module.cpp)
  target_compile_features(hexlab_python PRIVATE cxx_std_20)
  target_include_directories(hexlab_python PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
  target_link_libraries(hexlab_python PRIVATE hexlab::automation hexlab::debugger Python3::Python)
  if(WIN32)
    # Embedded CPython's import library does not copy its runtime DLL. Keep the
    # runner self-contained alongside the debugger runtime it already ships.
    get_filename_component(HEXLAB_PYTHON_RUNTIME_DIR "${Python3_EXECUTABLE}" DIRECTORY)
    set(HEXLAB_PYTHON_RUNTIME_DLL
      "${HEXLAB_PYTHON_RUNTIME_DIR}/python${Python3_VERSION_MAJOR}${Python3_VERSION_MINOR}.dll")
    if(NOT EXISTS "${HEXLAB_PYTHON_RUNTIME_DLL}")
      message(FATAL_ERROR "Embedded Python runtime DLL not found: ${HEXLAB_PYTHON_RUNTIME_DLL}")
    endif()
    add_custom_command(TARGET hexlab_python POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${HEXLAB_PYTHON_RUNTIME_DLL}"
        "$<TARGET_FILE_DIR:hexlab_python>"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_debugger>" "$<TARGET_FILE_DIR:hexlab_python>")
  endif()
  install(TARGETS hexlab_python RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

option(HEXLAB_BUILD_AUTOMATION_EXAMPLES "Build native automation SDK examples" OFF)
if(HEXLAB_BUILD_AUTOMATION_EXAMPLES)
  add_executable(hexlab_resume_inventory examples/resume_inventory.cpp)
  target_link_libraries(hexlab_resume_inventory PRIVATE hexlab::automation)
endif()

if(BUILD_TESTING)
  add_executable(hexlab_automation_tests tests/api_tests.cpp)
  target_link_libraries(hexlab_automation_tests PRIVATE hexlab::automation)
  add_test(NAME automation_api COMMAND hexlab_automation_tests)
  add_executable(hexlab_automation_graph_tests tests/graph_tests.cpp)
  target_link_libraries(hexlab_automation_graph_tests PRIVATE hexlab::automation)
  add_test(NAME automation_graph COMMAND hexlab_automation_graph_tests)
  if(HEXLAB_ENABLE_PYTHON_AUTOMATION)
    add_test(NAME automation_python COMMAND hexlab_python "${CMAKE_CURRENT_SOURCE_DIR}/tests/python_tests.py" sentinel)
    add_test(NAME automation_python_errors COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/console_tests.py" "$<TARGET_FILE:hexlab_python>")
    add_test(NAME automation_python_graph COMMAND hexlab_python "${CMAKE_CURRENT_SOURCE_DIR}/tests/graph_tests.py")
    set_tests_properties(automation_python automation_python_errors PROPERTIES TIMEOUT 120)
  endif()
endif()
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/../../docs/python-automation.md"
              "${CMAKE_CURRENT_SOURCE_DIR}/../../docs/python-automation-batches.md"
              "${CMAKE_CURRENT_SOURCE_DIR}/../../docs/python-type-import.md"
              "${CMAKE_CURRENT_SOURCE_DIR}/../../docs/python-history-automation-2026-10-24.md"
              "${CMAKE_CURRENT_SOURCE_DIR}/../../docs/python-stack-analysis.md"
              "${CMAKE_CURRENT_SOURCE_DIR}/../../docs/python-debug-information.md"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/docs")
install(DIRECTORY examples/ DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/examples/python"
  PATTERN "*.cpp" EXCLUDE)
install(FILES examples/resume_inventory.cpp DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/examples/native")
install(FILES README-workflow-state.md DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/docs")
install(FILES README-annotation-import.md DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/docs")
