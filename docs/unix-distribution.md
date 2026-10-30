# Linux and macOS distribution targets

The native CMake targets assemble the platform packages in the build tree's
`packages/` directory. Build a Linux distribution with:

```sh
cmake --build out/build/linux-desktop --target hexlab_linux_distribution
```

Linux desktop configurations use the configured CPack generators and produce
both the relocatable TGZ and Debian package. Linux headless configurations
produce the TGZ. The Debian package installs under `/usr` and uses
`dpkg-shlibdeps` to declare host shared-library dependencies. The TGZ keeps the
tools in `bin/`, HexLab and wxWidgets shared libraries in `lib/`, and notices
and documentation in `share/hexlab/`. Its executables use `$ORIGIN` runtime
paths to resolve the packaged HexLab libraries after extraction.

An RPM package can be added to either Linux configuration by enabling
`HEXLAB_BUILD_RPM_PACKAGE=ON`. CMake then requires `rpmbuild` on `PATH`, and
`hexlab_linux_distribution` creates the RPM alongside the configured TGZ and
DEB outputs. For example, configure a desktop release with:

```sh
cmake --preset linux-desktop -DHEXLAB_BUILD_RPM_PACKAGE=ON
cmake --build out/build/linux-desktop --target hexlab_linux_distribution
```

The RPM uses the standard `/usr` install layout and RPM's automatic shared
library dependency metadata. The option is Linux-only and off by default;
Debian and TGZ packaging do not require RPM tooling.

Build a macOS desktop distribution with:

```sh
cmake --build out/build/macos-desktop --target hexlab_macos_distribution
```

This target first creates the relocatable TGZ and then wraps that install tree
as `packages/HexLab.app.zip`. The `.app` contains the desktop executable and
CLI/debug tools in `Contents/MacOS`, bundled HexLab and wxWidgets libraries in
`Contents/lib`, and documentation, headers, and notices in `Contents/Resources`.
Its manifest describes those bundle-relative locations. The TGZ remains
available alongside the Finder bundle. On a headless macOS configuration, the
same `hexlab_macos_distribution` target creates only the TGZ.

Linux and macOS shared-library install names remain platform-native: Linux
uses `$ORIGIN` paths, macOS uses `@loader_path`, and neither package attempts to
bundle operating-system libraries. Linux system dependencies are declared by
the Debian package; TGZ users must provide the host libraries required by their
distribution. The macOS app archive is unsigned and not notarized, so Gatekeeper
may require the user to approve it before first launch.
