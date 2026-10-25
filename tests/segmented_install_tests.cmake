if(NOT IS_ABSOLUTE "${PREFIX}" OR NOT IS_DIRECTORY "${PREFIX}/bin" OR NOT IS_DIRECTORY "${TEST_BIN}")
  message(FATAL_ERROR "Supply absolute installed PREFIX and built TEST_BIN")
endif()
set(validation "${PREFIX}/validation/segmented")
file(MAKE_DIRECTORY "${validation}/tools")
set(ENV{PATH} "${PREFIX}/bin;$ENV{PATH}")
foreach(kind IN ITEMS x86_segments image_domains x86_16_decoder raw_profiles
    segmented_project segmented_recovery segmented_navigation open_profile)
  set(tool "hexlab_${kind}_tests.exe")
  file(COPY "${TEST_BIN}/${tool}" DESTINATION "${validation}/tools")
  execute_process(COMMAND "${validation}/tools/${tool}" WORKING_DIRECTORY "${validation}"
    RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 45)
  if(NOT "${status}" STREQUAL "0")
    message(FATAL_ERROR "Installed ${kind}: ${status}; ${output}; ${error}")
  endif()
  message(STATUS "${kind}: ${output}")
endforeach()
foreach(version IN ITEMS 1 2 3 4 5)
  file(COPY "${CMAKE_CURRENT_LIST_DIR}/fixtures/derived_v${version}.hxdc" DESTINATION "${validation}")
endforeach()
file(COPY "${CMAKE_CURRENT_LIST_DIR}/fixtures/derived_v3_provider.so"
  "${CMAKE_CURRENT_LIST_DIR}/fixtures/derived_v5_input.o" DESTINATION "${validation}")
file(COPY "${TEST_BIN}/hexlab_project_derived_cache_tests.exe" DESTINATION "${validation}/tools")
execute_process(COMMAND "${validation}/tools/hexlab_project_derived_cache_tests.exe"
  "${validation}/derived_v1.hxdc" "${validation}/derived_v2.hxdc"
  "${validation}/derived_v3.hxdc" "${validation}/derived_v3_provider.so"
  "${validation}/derived_v4.hxdc" "${validation}/derived_v5.hxdc" "${validation}/derived_v5_input.o"
  WORKING_DIRECTORY "${validation}"
  RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 45)
if(NOT "${status}" STREQUAL "0")
  message(FATAL_ERROR "Installed old-cache migration: ${status}; ${output}; ${error}")
endif()
message(STATUS "Old cache compatibility: ${output}")
file(COPY "${TEST_BIN}/hexlab_x86_segment_cpu_tests.exe" "${TEST_BIN}/hexlab_x86_16_cpu_tests.exe"
  DESTINATION "${validation}/tools")
set(QEMU "${CMAKE_CURRENT_LIST_DIR}/../out/tools/qemu-11.1.0-test/qemu-system-i386.exe")
set(NASM "${CMAKE_CURRENT_LIST_DIR}/../out/tools/nasm-3.02-test/nasm-3.02/nasm.exe")
set(BOCHS "${CMAKE_CURRENT_LIST_DIR}/../out/tools/bochs-3.1-test/bochs.exe")
set(ASSEMBLY "${CMAKE_CURRENT_LIST_DIR}/fixtures/x86_16_oracle/boot.asm")
set(CHECKER "${validation}/tools/hexlab_x86_segment_cpu_tests.exe")
set(ARTIFACTS "${validation}/oracle")
include("${CMAKE_CURRENT_LIST_DIR}/x86_segment_oracle.cmake")
execute_process(COMMAND "${validation}/tools/hexlab_x86_16_cpu_tests.exe" "${ARTIFACTS}/measurements.txt"
  RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 10)
if(NOT "${status}" STREQUAL "0")
  message(FATAL_ERROR "Installed decoder/CPU agreement: ${status}; ${output}; ${error}")
endif()
message(STATUS "Installed decoder/CPU agreement: ${output}")
