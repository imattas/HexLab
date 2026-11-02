# Windows and Linux Host Support

HexLab supports running as a host application on Windows and Linux only. The dormant Darwin native debugger implementation should be removed from the source tree. Historical debugger notes may remain clearly labeled as unsupported history. The existing CMake host gate and Windows/Linux backend selection remain authoritative. Mach-O parsing and Apple-target binary analysis remain supported on Windows and Linux.

Approaches considered: keep the unused Darwin source as archival code; or remove the dormant implementation and retain only clearly labeled historical docs. Remove the dormant source because the project no longer supports macOS as a host, and the implementation is not compiled by any supported build. Preserve Mach-O support because it analyzes input file formats rather than selecting a host platform.

Validation: inspect tracked references for dangling links and run the existing Windows and WSL builds if source/build configuration changes require it. Do not run tests.
