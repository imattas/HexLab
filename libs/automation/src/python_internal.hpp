#pragma once
#include <memory>
#include <stop_token>
// CPython's official Windows installation ships the release import library.
// Keep HexLab's own Debug runtime; only suppress Python's debug-library pragma.
#if defined(_MSC_VER) && defined(_DEBUG)
#define HEXLAB_RESTORE_DEBUG
#undef _DEBUG
#endif
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#ifdef HEXLAB_RESTORE_DEBUG
#define _DEBUG
#undef HEXLAB_RESTORE_DEBUG
#endif
extern "C" PyObject* PyInit__hexlab();

namespace hexlab::automation::python {
PyObject* make_stop_source_capsule(std::shared_ptr<std::stop_source> source);
}
