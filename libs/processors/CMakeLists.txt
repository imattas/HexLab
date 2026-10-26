hexlab_add_library(processors SOURCES src/x64_prefixes.cpp src/x64_operands.cpp src/x64_decode.cpp src/x64_x87.cpp src/x64_simd.cpp
  src/x64_arithmetic.cpp src/x64_bitops.cpp src/x64_flow.cpp src/x87_semantics.cpp src/format.cpp src/dispatch.cpp
  src/a64_decode.cpp src/a64_flow.cpp src/a64_data.cpp src/a64_integer.cpp src/a64_simd.cpp src/a64_format.cpp
  src/arm32_decode.cpp src/arm32_data.cpp src/arm32_semantics.cpp src/arm32_memory.cpp src/arm32_format.cpp
  src/thumb_decode.cpp src/thumb_flow.cpp src/thumb_data.cpp src/thumb_memory.cpp src/riscv.cpp src/riscv_semantics.cpp src/mips32.cpp src/mips64.cpp src/mips32_semantics.cpp src/mips64_semantics.cpp src/ppc.cpp src/m6502.cpp src/m6502_semantics.cpp
  src/wasm.cpp src/dex.cpp src/jvm.cpp src/zydis_fallback.cpp src/capstone_fallback.cpp DEPENDS hexlab::core Zydis capstone_static)

