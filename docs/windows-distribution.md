# Windows distribution package

Windows builds expose the `hexlab_windows_distribution` CMake target. It builds
the command-line tool, debug server, and desktop application when enabled, then
asks CPack to assemble the relocatable ZIP under `packages/` in the build tree.
The archive name includes the product version, Windows target, and architecture.

For Visual Studio, build the release package with:

```powershell
cmake --build out/build --config Release --target hexlab_windows_distribution
```

For a single-configuration generator, configure a Release build and run:

```powershell
cmake --build out/build --target hexlab_windows_distribution
```

The ZIP extracts to one versioned package directory with this layout:

```text
HexLab-<version>-Windows-<arch>/
  bin/
    hexlab_cli.exe
    hexlab_debug_server.exe
    hexlab.exe                         # when HEXLAB_BUILD_DESKTOP=ON
    hexlab_*.dll
    hexlab_sqlite3.dll
    wx*.dll                            # desktop builds
    other non-system runtime DLLs
  share/hexlab/
    package-manifest.json
    package-files.sha256
    docs/
    licenses/
```

The install rules place HexLab engine DLLs, SQLite, wxWidgets, and any other
non-system DLLs discovered from the installed executables and shared-library
closure together in `bin`. The CMake runtime dependency scan excludes Windows
API-set forwarders and DLLs from Windows system directories. The package
contains the command-line tool and debug server in both desktop and headless
builds; `hexlab.exe`, wxWidgets DLLs, and their license notices are included
only when the desktop is enabled. The docs and dependency notices are installed
beside the binaries under `share/hexlab`.

Extract the ZIP and launch either executable from `bin`; no PATH edits or
machine-wide DLL installation are needed for bundled dependencies. The package
does not include the Microsoft Visual C++ 2022 Redistributable. Install the
matching architecture of that redistributable on the target machine. Build and
ship Release configuration packages; Debug builds depend on the developer's
installed debug runtime. Optional Python automation also has a separate Python
runtime requirement described in [Python automation](python-automation.md).

`package-manifest.json` records tools, runtime targets, notices, and conditional
host requirements. `package-files.sha256` lists the packaged files and checks
for accidental omission or corruption after extraction; it is an integrity
inventory, not a publisher signature. Plugins are distributed separately and
must match the plugin ABI version listed in the manifest.
