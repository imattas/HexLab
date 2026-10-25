execute_process(COMMAND "${GENERATOR}" "${FIXTURES}" RESULT_VARIABLE generated)
if(NOT "${generated}" STREQUAL "0")
  message(FATAL_ERROR "x64 SIMD fixture generation failed")
endif()
set(raw "${FIXTURES}/x64-simd.bin")
execute_process(COMMAND "${CLI}" disassemble "${raw}" --format raw --arch x86-64 --base 0x1000
  RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 20)
if(NOT "${status}" STREQUAL "0")
  message(FATAL_ERROR "x64 SIMD raw CLI returned ${status}: stdout='${output}', stderr='${error}'")
endif()
foreach(pattern IN ITEMS
    "paddd.*xmm0, xmm1"
    "movdqu.*xmm2, xmmword ptr \\[rax\\]"
    "addsd.*xmm3, xmm4"
    "movss.*xmm5, xmm6")
  if(NOT "${output}" MATCHES "${pattern}")
    message(FATAL_ERROR "x64 SIMD raw CLI output omitted '${pattern}': ${output}")
  endif()
endforeach()
if(NOT "${output}" MATCHES "pcmpeqd.*xmm0, xmm7")
  message(FATAL_ERROR "x64 SIMD raw CLI output omitted packed compare: ${output}")
endif()
if(NOT "${error}" STREQUAL "")
  message(FATAL_ERROR "x64 SIMD raw CLI wrote unexpected diagnostics: ${error}")
endif()
message(STATUS "x64 SIMD raw CLI decoded packed and scalar SSE forms")
