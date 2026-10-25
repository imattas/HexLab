file(MAKE_DIRECTORY "${ARTIFACTS}")
set(project "${ARTIFACTS}/references.hxproj")
file(REMOVE "${project}" "${project}-wal" "${project}-shm")
execute_process(COMMAND "${CHECKER}" --write-project "${project}" RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "Cannot create owned ELF project fixture: ${output}${error}")
endif()
execute_process(COMMAND "${CLI}" project references "${project}" --at va:1:0x10 --direction outgoing
  RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT status EQUAL 3 OR NOT output MATCHES "kind=relocation provenance=elf-relocation" OR
   NOT output MATCHES "symbol=external" OR NOT output MATCHES "elf-record=file:0x" OR NOT error STREQUAL "")
  message(FATAL_ERROR "CLI lost unresolved ELF symbol/table provenance: status=${status}\n${output}\n${error}")
endif()
execute_process(COMMAND "${CLI}" project references "${project}" --at va:1:0x8 --direction outgoing
  RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT status EQUAL 3 OR NOT output MATCHES "va:2:0x0 kind=relocation provenance=elf-relocation" OR
   NOT output MATCHES "symbol=callee" OR NOT error STREQUAL "")
  message(FATAL_ERROR "CLI lost declared ELF data relocation target: status=${status}\n${output}\n${error}")
endif()
