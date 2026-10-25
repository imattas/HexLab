# Python automation implementation plan

Goal: implement the approved optional Python automation subsystem inline in the
shared workspace, owning libs/automation and distinct tests/docs only.

1. Add focused real-project tests and standalone CMake integration; observe the
   missing-bridge RED build. Implement automation/api.hpp and api.cpp using existing
   ProjectStore and ProjectSession contracts; validate version, paging, read limits,
   selectors, readonly commands, undo/redo and exports.
2. Add a Python end-to-end script before the runner; observe missing executable
   RED. Implement a built-in capsule module and Python Project facade, then a
   script/interactive runner behind HEXLAB_ENABLE_PYTHON_AUTOMATION. Test argument
   propagation, traceback/nonzero status, native error mapping and persistence.
3. Verify optional-OFF standalone build and focused CTest, then optional-ON build
   and CTest. Document exact build/integration commands, API and limitations.
   Report parent integration edits without editing shared CMake/capability files.

File responsibilities: libs/automation/CMakeLists.txt owns optional discovery,
native library and isolated tests; include/hexlab/automation/api.hpp and src/api.cpp
own the bridge; python/hexlab.py owns the stable Python facade; src/python_module.cpp
owns CPython conversion/lifetime; src/console.cpp owns interpreter lifecycle;
tests own real project fixtures and error/console checks; examples owns runnable
user script. docs/python-automation.md records public behavior and evidence.
