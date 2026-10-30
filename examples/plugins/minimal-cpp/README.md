# Minimal C++ plugin

This is the smallest standalone C++ module using the installed HexLab SDK. It
registers one `hello-cpp` action that logs a message through the host API. When the host exposes the ABI 1.12 menu callback, it also registers the same callback under `Extensions > Examples > Native SDK`; older hosts continue to load the action-only module.

First build and install HexLab, then configure this directory with that install
as its package prefix:

```sh
cmake -S examples/plugins/minimal-cpp -B build/minimal-plugin -DCMAKE_PREFIX_PATH=/path/to/hexlab-install
cmake --build build/minimal-plugin
cmake --install build/minimal-plugin --prefix /path/to/plugin-install
```

The install contains the native module and its `.hexlab-plugin` metadata under
`lib/hexlab/plugins` (or the platform's library directory). Point HexLab's
plugin scan command or plugin directory at that folder. The SDK itself is
provided by `HexLabPluginSdk` and the imported target `hexlab::plugin_sdk`.
