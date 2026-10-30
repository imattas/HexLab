# Flat image loader C++ plugin

This standalone module demonstrates the ABI 1.10 loader image provider. It
claims a small `HLF1` file format, maps the bytes after the four-byte header as
one read/execute x86 32-bit segment at `0x1000`, and selects that address as the
entry point. The callback validates the input again, checks cancellation, and
returns an explicit failure for unsupported or malformed input.

The example intentionally handles only an untransformed, contiguous code
image. It does not claim relocation, mixed permissions, zero-filled tails, or
other architecture modes. To try it, install the module and sidecar manifest
into a plugin directory, create a file beginning with `HLF1` followed by x86
machine code, and choose the `example-flat` loader format.

Build and install against a HexLab installation that includes the plugin SDK
package:

```sh
cmake -S examples/plugins/flat-image-loader-cpp -B build/flat-image-loader-plugin \
  -DCMAKE_PREFIX_PATH=/path/to/hexlab-install
cmake --build build/flat-image-loader-plugin
cmake --install build/flat-image-loader-plugin --prefix /path/to/plugin-install
```
