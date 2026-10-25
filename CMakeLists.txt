cmake_minimum_required(VERSION 3.24)
project(HexLab VERSION 0.1.0 LANGUAGES C CXX)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR "Use an out-of-source build directory.")
endif()
option(HEXLAB_BUILD_DESKTOP "Build the wxWidgets desktop" ON)
option(HEXLAB_ENABLE_GUI_TESTS "Run tests requiring an interactive desktop" OFF)
option(HEXLAB_BUILD_NSIS_INSTALLER "Include an NSIS installer in Windows CPack output" OFF)
if(WIN32)
  set(_hexlab_oracle_default ON)
else()
  set(_hexlab_oracle_default OFF)
endif()
option(HEXLAB_ENABLE_PINNED_LLVM_ORACLES "Run differential tests requiring the exact pinned LLVM tool binaries" ${_hexlab_oracle_default})
unset(_hexlab_oracle_default)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")
include(GNUInstallDirs)
include(GenerateExportHeader)
include(cmake/HexLabLibrary.cmake)
include(CTest)
add_library(hexlab_options INTERFACE)
target_compile_features(hexlab_options INTERFACE cxx_std_20)
target_compile_options(hexlab_options INTERFACE
  $<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/W4;/permissive-;/utf-8>
  $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic>)
include(cmake/SQLite.cmake)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_DECODER ON CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_ENCODER OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_FORMATTER ON CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_AVX512 ON CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_KNC ON CACHE BOOL "" FORCE)
add_subdirectory(third_party/zydis EXCLUDE_FROM_ALL)
add_subdirectory(third_party/miniz EXCLUDE_FROM_ALL)
install(FILES third_party/zydis/LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/licenses/zydis")
install(FILES third_party/zydis/dependencies/zycore/LICENSE
  DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/licenses/zycore")
install(FILES third_party/miniz/LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/licenses/miniz")
install(FILES libs/firmware/EDK2-LICENSE.txt
  DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/licenses/firmware")
get_property(_hexlab_had_build_shared_libs CACHE BUILD_SHARED_LIBS PROPERTY TYPE SET)
if(_hexlab_had_build_shared_libs)
  set(_hexlab_saved_build_shared_libs "${BUILD_SHARED_LIBS}")
endif()
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "" FORCE)
set(CAPSTONE_INSTALL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
foreach(_arch ARM ARM64 MIPS PPC X86 MOS65XX RISCV)
  set(CAPSTONE_${_arch}_SUPPORT ON CACHE BOOL "" FORCE)
endforeach()
add_subdirectory(third_party/capstone EXCLUDE_FROM_ALL)
if(_hexlab_had_build_shared_libs)
  set(BUILD_SHARED_LIBS "${_hexlab_saved_build_shared_libs}" CACHE BOOL "" FORCE)
else()
  unset(BUILD_SHARED_LIBS CACHE)
endif()
unset(_hexlab_had_build_shared_libs)
unset(_hexlab_saved_build_shared_libs)
install(FILES third_party/capstone/LICENSE.TXT third_party/capstone/LICENSE_LLVM.TXT
  DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/licenses/capstone")
add_subdirectory(libs)
if(HEXLAB_BUILD_DESKTOP)
  include(cmake/WxWidgets.cmake)
endif()
add_subdirectory(apps)
if(BUILD_TESTING)
  add_subdirectory(tests)
endif()
install(FILES README.md docs/building.md docs/project-cli.md docs/project-format.md docs/project-analysis-validation.md docs/third-party.md docs/capabilities.csv docs/foundation-validation.md docs/binary-analysis-validation.md docs/x64-coverage.csv docs/x86-32-coverage.csv docs/x86-32-validation.md docs/x86-loop-control-flow.md docs/analysis-large-image-performance.md libs/decompiler/docs/post-tested-loop-exit-paths.md
  docs/x86-profiles.md docs/segmented-analysis-validation.md docs/incremental-metadata-invalidation.md docs/capstone-semantic-fallback.md docs/x86-16-coverage.csv docs/x86-repeated-strings.md
  docs/binary-comparison.md docs/binary-comparison-block-instructions.md docs/binary-comparison-relocation-masks.md
  docs/elf-analysis-validation.md docs/elf-runtime-relocations.md docs/elf-debug-frame.md libs/loaders/docs/elf-riscv-runtime-relocations.md docs/elf-core-dumps.md docs/elf-symbol-versions.md docs/elf-rtti.md docs/macho-analysis-validation.md docs/macho-static-linking.md docs/ar-archive-validation.md docs/coff-static-linking.md docs/coff-arm64-static-linking.md
  docs/pdb-validation.md docs/pdb-types-validation.md docs/pdb-ipi-function-identifiers.md docs/pdb-ipi-project-workflow.md docs/switch-analysis-validation.md docs/relocation-backed-switches.md docs/archive-workflow-validation.md apps/cli/plugin-dependency-preflight.md apps/cli/flirt-catalog-sets.md apps/cli/macho-module-symbol-resolution.md
  docs/debugger-stepping.md docs/debugger-hardware-breakpoints.md docs/debugger-watchpoints.md docs/debugger-breakpoint-workflow.md docs/debugger-platforms.md libs/debugger/docs/windows-x64-simd-registers.md libs/debugger/docs/darwin-backend.md libs/debugger/docs/linux-aarch64-backend.md libs/debugger/docs/linux-x86-lifecycle.md libs/debugger/docs/elf-aarch64-stack-frames.md libs/debugger/docs/elf-arm-riscv-stack-frames.md libs/debugger/docs/remote-memory-map.md docs/debugger-macos.md docs/debugger-darwin.md docs/debugger-linux-aarch64.md docs/linux-debugger-termination.md docs/debugger-rsp.md docs/rsp-process-selection.md docs/debugger-pdb-inline-locals.md docs/plugin-sdk.md docs/plugin-dependency-management.md docs/plugin-dependency-activation.md docs/collaboration-ui.md docs/plugin-candidate-preflight.md
  docs/managed-loader-validation.md docs/managed-cil-exception-regions.md docs/managed-cil-user-strings.md docs/managed-cil-call-semantics.md docs/managed-cil-field-references.md docs/managed-cil-function-pointers.md docs/decompiler-type-recovery.md docs/decompiler-stack-type-provenance.md docs/decompiler-cross-abi-calls.md docs/decompiler-cross-abi-stack-arguments.md docs/decompiler-memory-ssa.md docs/decompiler-structuring.md docs/decompiler-control-flow-unflattening.md libs/decompiler/docs/wasm-parameter-reads.md libs/decompiler/docs/jvm-stack-transport.md libs/loaders/docs/macho-build-versions.md apps/desktop/disassembly-page-export.md apps/desktop/source-line-breakpoints.md docs/pseudocode-source-navigation.md
  docs/header-import.md docs/header-non-type-alias-templates.md docs/header-alignment-import.md docs/header-pack-semantics.md docs/header-cpp-declarations.md docs/header-cpp-member-import.md docs/cpp-template-import.md docs/header-non-type-specializations.md docs/header-anonymous-namespaces.md docs/type-authoring.md docs/type-layout.md docs/bitfield-layout.md docs/python-automation.md docs/python-automation-batches.md docs/project-history-audit.md docs/project-history-audit-cli.md docs/desktop-project-history-2026-10-24.md docs/python-history-automation-2026-10-24.md libs/analysis/docs/search-ascii-case-folding.md libs/analysis/docs/riscv-jump-tables.md libs/analysis/docs/windows-1250-string-detection.md
  docs/cil-decoder-validation.md docs/jvm-stack-manipulation.md
  docs/dwarf-v4-import.md docs/dwarf-v5-import.md docs/dwarf-package-catalog.md docs/dwarf-cross-unit-references.md docs/dwarf-entry-value-locations.md docs/debugger-inspection.md docs/minidump-analysis.md docs/native-thread-control.md docs/project-breakpoints.md docs/pe-bound-imports.md docs/pe-load-configuration.md docs/pe-safe-seh.md
  docs/riscv64-coverage.md docs/riscv-vector-configuration.md docs/riscv-decompiler.md docs/riscv-zbb-count-operations.md docs/pe-inspection.md docs/pe-certificates.md docs/pe-dynamic-value-relocations.md docs/pe-relocations.md
  docs/wasm-analysis.md docs/wasm-decompilation.md docs/jvm-invokedynamic-lifting.md docs/jvm-stack-map-tables.md docs/jvm-analysis.md docs/dex-scalar-conversions.md docs/linux-x86-thread-resume-schedules.md libs/debugger/docs/thread-resume-schedules.md docs/managed-cil-type-operations.md docs/pe-version-resource-strings.md docs/dex-object-lifting.md docs/jvm-object-and-constant-operations.md
  docs/x64-condition-semantics.md docs/debugger-lifecycle.md docs/debugger-dwarf-locals.md docs/debug-server.md docs/memory-search.md docs/signatures.md docs/symbol-demangling.md docs/itanium-template-packs.md docs/abi-classification.md docs/vector-abi-classification.md docs/project-exchange.md docs/project-backup.md docs/mips32.md docs/decompiler-opaque-predicates.md
  docs/mips64.md docs/mips-delay-slots.md docs/m6502.md docs/x87-decoder-coverage.md docs/decompiler-x87.md docs/powerpc.md docs/x64-simd-coverage.md docs/arm64-pe-unwind.md docs/pe-exception-directory.md docs/pe-msvc-rtti.md docs/pe-unwind-info.md docs/macho-compact-unwind.md docs/macho-eh-frame.md docs/macho-link-eh-frame.md docs/pe-live-unwind.md docs/desktop-navigation.md docs/desktop-pseudocode-navigation.md docs/graph-view.md docs/graph-layout-persistence.md docs/graph-multiselection.md docs/uefi-standard-compression.md libs/loaders/docs/pe-coff-symbols.md libs/firmware/docs/uefi-ffs-data-checksums.md libs/firmware/docs/uefi-tiano-compression.md
  docs/architecture-xrefs.md docs/reference-range-queries.md docs/reference-producer-provenance.md libs/analysis/docs/non-x86-reference-provenance.md libs/analysis/docs/incremental-certified-revisions.md libs/analysis/docs/macho-objc-32bit.md libs/analysis/docs/pe-amd64-chained-function-chunks.md docs/decompiler-optimization.md docs/decompiler-arithmetic-predicates.md docs/function-recovery-multiarc.md docs/function-recovery-initializers.md docs/function-recovery-root-conflicts.md docs/function-call-neighborhood.md docs/arm-predicated-call-recovery.md docs/arm32-decompiler.md docs/multi-monitor-workflow.md docs/a64-pair-memory-lifting.md docs/desktop-source-code.md docs/source-line-assembly.md docs/desktop-analysis-issues.md docs/desktop-accessibility.md docs/a64-simd-floating.md docs/arm-literal-pointer-analysis.md docs/macho-objc-runtime.md docs/type-library.md docs/desktop-type-library.md docs/uefi-firmware-volume.md docs/cli-module-dependencies.md docs/module-symbol-resolution.md docs/elf-module-symbol-resolution.md docs/a64-scalar-condition-arithmetic.md docs/elf-android-packed-relocations.md docs/dwarf-inheritance-layout.md docs/navigation-view-history.md docs/macho-subtractor-relocations.md docs/macho-dyld-chained-bounds.md docs/desktop-project-backups.md docs/arm-control-flow-xrefs.md docs/pdb-inline-site-local-provenance.md docs/uefi-section-text-metadata.md docs/function-recovery-elf-symbol-extents.md docs/binary-comparison-confidence-filters.md docs/desktop-history-audit.md docs/flirt-catalog-composition.md docs/desktop-byte-patching.md
  apps/desktop/analysis-issues-export.md apps/desktop/analysis-issues-navigation.md libs/database/HISTORY.md libs/database/HISTORY_SAVE.md docs/project-history-save-cli.md
  DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/docs")

# Produce a relocatable, multi-file archive of the complete install tree.
# Runtime libraries remain separate files beside the tools by design.
set(CPACK_PACKAGE_NAME "HexLab")
set(CPACK_PACKAGE_VENDOR "HexLab project")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "C++ reverse-engineering workbench")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/docs/third-party.md")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "HexLab")
set(CPACK_MONOLITHIC_INSTALL ON)
set(CPACK_PACKAGE_DIRECTORY "${PROJECT_BINARY_DIR}/packages")
if(NOT CPACK_GENERATOR)
  if(WIN32)
    set(CPACK_GENERATOR ZIP)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND HEXLAB_BUILD_DESKTOP)
    # Linux desktop releases are both a system-installable Debian package and
    # a relocatable archive for manual installs. Headless and macOS builds keep
    # the portable TGZ format.
    set(CPACK_GENERATOR "TGZ;DEB")
  else()
    set(CPACK_GENERATOR TGZ)
  endif()
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  # Package paths are rooted at / (usr/bin, usr/lib, usr/share) even though
  # ordinary developer installs continue to use CMAKE_INSTALL_PREFIX.
  set(CPACK_PACKAGING_INSTALL_PREFIX "/")
  set(CPACK_DEBIAN_PACKAGE_NAME "hexlab")
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER "HexLab project maintainers")
  set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
  set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
  # dpkg-shlibdeps derives the host-system runtime dependencies from the
  # installed executables and bundled shared libraries.
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
endif()
if(HEXLAB_BUILD_NSIS_INSTALLER)
  if(NOT WIN32)
    message(FATAL_ERROR "HEXLAB_BUILD_NSIS_INSTALLER is supported only on Windows.")
  endif()
  find_program(HEXLAB_MAKENSIS_EXECUTABLE NAMES makensis makensis.exe)
  if(NOT HEXLAB_MAKENSIS_EXECUTABLE)
    message(FATAL_ERROR "HEXLAB_BUILD_NSIS_INSTALLER requires NSIS (makensis) on PATH.")
  endif()
  if(NOT "NSIS" IN_LIST CPACK_GENERATOR)
    list(APPEND CPACK_GENERATOR NSIS)
  endif()
  set(CPACK_NSIS_EXECUTABLE "${HEXLAB_MAKENSIS_EXECUTABLE}")
  set(CPACK_NSIS_PACKAGE_NAME "HexLab ${PROJECT_VERSION}")
  set(CPACK_NSIS_DISPLAY_NAME "HexLab ${PROJECT_VERSION}")
  set(CPACK_NSIS_MODIFY_PATH OFF)
  set(CPACK_PACKAGE_EXECUTABLES "hexlab" "HexLab" "hexlab_cli" "HexLab CLI")
  set(CPACK_NSIS_MENU_LINKS
    "share/hexlab/docs/building.md" "Build and usage guide")
endif()
set(_hexlab_target_arch "${CMAKE_GENERATOR_PLATFORM}")
if(NOT _hexlab_target_arch)
  set(_hexlab_target_arch "${CMAKE_SYSTEM_PROCESSOR}")
endif()
string(TOLOWER "${_hexlab_target_arch}" _hexlab_target_arch)
if(_hexlab_target_arch MATCHES "^(aarch64|arm64)$")
  set(_hexlab_package_arch arm64)
elseif(_hexlab_target_arch MATCHES "^(x86_64|amd64|x64)$")
  set(_hexlab_package_arch x64)
elseif(_hexlab_target_arch MATCHES "^(i[3-6]86|win32|x86)$")
  set(_hexlab_package_arch x86)
elseif(_hexlab_target_arch)
  string(REGEX REPLACE "[^a-z0-9]+" "_" _hexlab_package_arch "${_hexlab_target_arch}")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(_hexlab_package_arch unknown64)
else()
  set(_hexlab_package_arch unknown32)
endif()
set(_hexlab_package_file_name "HexLab-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${_hexlab_package_arch}")
set(CPACK_PACKAGE_FILE_NAME "${_hexlab_package_file_name}")

# Publish a machine-readable description of the multi-file install tree. Keep
# the native plugin ABI version sourced from the public SDK header.
set(_hexlab_manifest_tools
  "    {\"name\": \"hexlab_cli${CMAKE_EXECUTABLE_SUFFIX}\", \"role\": \"command-line\"},\n    {\"name\": \"hexlab_debug_server${CMAKE_EXECUTABLE_SUFFIX}\", \"role\": \"debug-server\"}")
if(HEXLAB_BUILD_DESKTOP)
  string(APPEND _hexlab_manifest_tools
    ",\n    {\"name\": \"hexlab${CMAKE_EXECUTABLE_SUFFIX}\", \"role\": \"desktop\"}")
endif()
set(_hexlab_manifest_components
  "core;image;firmware;loaders;database;processors;decompiler;types;analysis;workspace;automation;debugger;plugins;symbols;compare")
set(_hexlab_manifest_runtime_targets)
foreach(_component IN LISTS _hexlab_manifest_components)
  if(_hexlab_manifest_runtime_targets)
    string(APPEND _hexlab_manifest_runtime_targets ",\n")
  endif()
  string(APPEND _hexlab_manifest_runtime_targets "    \"hexlab_${_component}\"")
endforeach()
string(APPEND _hexlab_manifest_runtime_targets ",\n    \"hexlab_sqlite3\"")
if(HEXLAB_BUILD_DESKTOP)
  string(APPEND _hexlab_manifest_runtime_targets
    ",\n    \"wxbase\",\n    \"wxcore\",\n    \"wxaui\"")
endif()
file(STRINGS "${PROJECT_SOURCE_DIR}/libs/plugins/include/hexlab/plugins/plugin_abi.h"
  _hexlab_plugin_abi_major_line REGEX "^#define HEXLAB_PLUGIN_ABI_MAJOR [0-9]+u$")
file(STRINGS "${PROJECT_SOURCE_DIR}/libs/plugins/include/hexlab/plugins/plugin_abi.h"
  _hexlab_plugin_abi_minor_line REGEX "^#define HEXLAB_PLUGIN_ABI_MINOR [0-9]+u$")
string(REGEX MATCH "[0-9]+" HEXLAB_PLUGIN_ABI_MAJOR "${_hexlab_plugin_abi_major_line}")
string(REGEX MATCH "[0-9]+" HEXLAB_PLUGIN_ABI_MINOR "${_hexlab_plugin_abi_minor_line}")
if(NOT HEXLAB_PLUGIN_ABI_MAJOR OR NOT HEXLAB_PLUGIN_ABI_MINOR)
  message(FATAL_ERROR "Could not read the native plugin ABI version from plugin_abi.h")
endif()
if(WIN32)
  set(_hexlab_manifest_runtime_dir "${CMAKE_INSTALL_BINDIR}")
else()
  set(_hexlab_manifest_runtime_dir "${CMAKE_INSTALL_LIBDIR}")
endif()
math(EXPR HEXLAB_PACKAGE_POINTER_BITS "${CMAKE_SIZEOF_VOID_P} * 8")
if(HEXLAB_BUILD_DESKTOP)
  set(HEXLAB_PACKAGE_HAS_DESKTOP true)
else()
  set(HEXLAB_PACKAGE_HAS_DESKTOP false)
endif()
set(HEXLAB_PACKAGE_ARCH "${_hexlab_package_arch}")
set(HEXLAB_PACKAGE_TOOLS "${_hexlab_manifest_tools}")
set(HEXLAB_PACKAGE_RUNTIME_TARGETS "${_hexlab_manifest_runtime_targets}")
set(HEXLAB_PACKAGE_RUNTIME_DIRECTORY "${_hexlab_manifest_runtime_dir}")
configure_file(cmake/package-manifest.json.in
  "${PROJECT_BINARY_DIR}/package-manifest.json" @ONLY)
install(FILES "${PROJECT_BINARY_DIR}/package-manifest.json"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab")
install(FILES docs/package-manifest.md DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/docs")
include(CPack)

if(BUILD_TESTING)
  if(WIN32 AND "ZIP" IN_LIST CPACK_GENERATOR)
    set(_hexlab_package_test_generator ZIP)
    set(_hexlab_package_extension ".zip")
  elseif("TGZ" IN_LIST CPACK_GENERATOR)
    set(_hexlab_package_test_generator TGZ)
    set(_hexlab_package_extension ".tar.gz")
  else()
    message(FATAL_ERROR "Package validation requires ZIP on Windows or TGZ elsewhere; configured generators: ${CPACK_GENERATOR}")
  endif()
  string(RANDOM LENGTH 12 ALPHABET 0123456789abcdef _hexlab_package_test_id)
  add_test(NAME package_archive
    COMMAND "${CMAKE_COMMAND}"
      "-DCPACK_COMMAND=${CMAKE_CPACK_COMMAND}"
      "-DCPACK_CONFIG=${PROJECT_BINARY_DIR}/CPackConfig.cmake"
      "-DCPACK_CONFIG_TYPE=$<CONFIG>"
      "-DCPACK_GENERATOR=${_hexlab_package_test_generator}"
      "-DARCHIVE=${PROJECT_BINARY_DIR}/packages/${_hexlab_package_file_name}${_hexlab_package_extension}"
      "-DEXTRACT_DIR=${PROJECT_BINARY_DIR}/package-tests/${_hexlab_package_test_id}"
      "-DEXPECT_DESKTOP=${HEXLAB_BUILD_DESKTOP}"
      -P "${PROJECT_SOURCE_DIR}/tests/package_archive_tests.cmake")
endif()


