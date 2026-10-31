# Windows and Linux Host Support

HexLab is supported as a host application on Windows and Linux only. CMake
configuration on other host operating systems must fail early with a clear
message. The project keeps target-format and processor support for Apple
binaries, including Mach-O; dropping the macOS host does not remove that
analysis capability.

Windows and Linux remain the only advertised and automated build, test, and
distribution hosts. Remove macOS presets, CI jobs, application packaging, and
host-specific support claims. Retain historical implementation notes when they
describe past work, but do not present them as current supported-host behavior.

The macOS-native debugger and platform-specific host paths are no longer part of
the supported application surface. Generic remote debugging, Mach-O parsing,
Apple processor profiles, and Macintosh text encodings remain where they serve
analysis of target binaries on Windows or Linux.
