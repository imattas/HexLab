execute_process(COMMAND "${POWERSHELL}" -NoProfile -File "${CMAKE_CURRENT_LIST_DIR}/graph_oracle.ps1" -Path "${GRAPH}"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 25)
if(NOT "${result}" STREQUAL "0")
  message(FATAL_ERROR "Independent graph JSON/layout check failed: ${result}\n${output}\n${error}")
endif()
