# Package manifest

Every installed tree and CPack archive includes `share/hexlab/package-manifest.json`.
It describes the build's target OS and architecture, the relative install layout,
the executable tools included, the shared runtime target names, whether the
desktop application is present, and the native plugin ABI version implemented by
the host. `schema_version` is independent of HexLab's product version and changes
when this JSON contract changes.

The manifest is generated from the CMake install layout and the plugin ABI
constants in `libs/plugins/include/hexlab/plugins/plugin_abi.h`. Tool entries
contain package-relative filenames and roles. Runtime target entries are CMake
target names without platform suffixes; use `runtime_directory` to locate their
installed shared-library files. On Windows, tools and shared runtime DLLs are in
`bin`; on Linux and macOS, tools are in `bin` and shared runtime libraries are in
the configured library directory. The manifest reports the package layout, not
every transitive system library required by the host operating system.

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
