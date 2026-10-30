# Package manifest

Every installed tree and CPack archive includes `share/hexlab/package-manifest.json`.
It describes the build's target OS and architecture, the relative install layout,
the executable tools included, the shared runtime target names, whether the
desktop application is present, and the native plugin ABI version implemented by
the host. `schema_version` is independent of HexLab's product version and changes
when this JSON contract changes. Version 2 adds `conditional_host_requirements`;
version 3 adds the exact package-relative notice inventory.

The manifest is generated from the CMake install layout and the plugin ABI
constants in `libs/plugins/include/hexlab/plugins/plugin_abi.h`. Tool entries
contain package-relative filenames and roles. Runtime target entries are CMake
target names without platform suffixes; use `runtime_directory` to locate their
installed shared-library files. On Windows, tools and shared runtime DLLs are in
`bin`; on Linux and macOS, tools are in `bin` and shared runtime libraries are in
the configured library directory. The manifest reports the package layout, not
every transitive system library required by the host operating system.
`conditional_host_requirements` describes known prerequisites whose condition
must be checked against `target`; it does not imply that the prerequisite applies
to every package. Windows builds made with MSVC require the Microsoft Visual C++
2022 Redistributable for the listed architecture. HexLab does not bundle that
redistributable. The package still needs fresh-machine validation on each
supported Windows configuration.

`notices.overview` points to the dependency summary, `notices.license_directory`
gives the notice root, and `notices.files` lists every notice/provenance file
expected in this package. The list is generated from whether the wxWidgets
desktop is included, so a command-line-only package does not claim desktop-only
wxWidgets notices.

Each install also writes `share/hexlab/package-files.sha256` after copying the
payload. It contains a SHA-256 checksum for every regular file in that install
tree, with paths relative to the install prefix; it excludes itself. The file
is generated for CPack staging as well, so it remains useful after extracting
or moving the multi-file package. On Linux, verify from the install prefix with
`sha256sum -c share/hexlab/package-files.sha256`. In PowerShell, run:

```powershell
$root = (Get-Location).Path
Get-Content share/hexlab/package-files.sha256 | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object {
  $parts = $_ -split '\s+', 2
  $path = Join-Path $root ($parts[1] -replace '/', '\\')
  $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $parts[0]) { throw "Package checksum mismatch: $($parts[1])" }
}
```

The inventory detects missing or modified files relative to the generated
install snapshot; it is not a publisher signature and does not authenticate who
created the archive.

Linux desktop CPack builds produce a Debian package and a relocatable TGZ.
The Debian package installs the tree under `/usr`, includes an XDG desktop
entry and scalable icon, and declares system shared-library dependencies
discovered from the executables and bundled libraries. The TGZ preserves the
same multi-library tree for manual extraction. Optional Python automation uses
the system CPython shared library when enabled at configure time; it is not a
bundled interpreter distribution.

The macOS desktop workflow retains the relocatable TGZ and also creates
`HexLab.app.zip` for Finder installs. The app bundle keeps `hexlab`, `hexlab_cli`,
and the debug server together in `Contents/MacOS`; the HexLab and wxWidgets
shared libraries are in `Contents/lib`, where the app's relative install names
resolve them after the bundle is moved. Headers and documentation are under
`Contents/Resources`, and the bundled package manifest is rewritten to describe
that layout. The app bundle is not code signed or notarized by CI, so it is a
review artifact rather than a ready-to-publish macOS release.

Plugins are optional, separately built native modules. The manifest identifies
the host ABI major/minor version and query symbol so a distribution or plugin
manager can select a compatible module. The package does not embed user plugins.
Windows packages still require the matching Microsoft Visual C++ Redistributable;
Debug builds also require the developer's installed Debug runtime.

On Windows, the `hexlab_windows_distribution` build target assembles the
relocatable ZIP from the configured CPack install tree. It includes the CLI and
debug server, the desktop and wxWidgets runtime when enabled, installed
non-system DLL dependencies, the package manifest and checksum inventory, and
the installed docs and notices. See [Windows distribution package](windows-distribution.md)
for the command and extracted layout.
