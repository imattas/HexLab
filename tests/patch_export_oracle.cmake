execute_process(COMMAND "${POWERSHELL}" -NoProfile -NonInteractive -ExecutionPolicy Bypass
  -File "${CMAKE_CURRENT_LIST_DIR}/patch_export_oracle.ps1" -Path "${ARTIFACTS}"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 25)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Independent patch export hash failed: ${output} ${error}")
endif()
