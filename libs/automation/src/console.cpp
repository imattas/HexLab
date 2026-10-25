#include "python_internal.hpp"
#include "facade.hpp"
#include <cstdio>
#ifdef _WIN32
#include <crtdbg.h>
#include <Windows.h>
#endif

#ifdef _WIN32
int wmain(int argc,wchar_t** argv) {
#else
int main(int argc,char** argv) {
#endif
#ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    _CrtSetReportMode(_CRT_ASSERT,_CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT,_CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_ERROR,_CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ERROR,_CRTDBG_FILE_STDERR);
#endif
    if(PyImport_AppendInittab("_hexlab",PyInit__hexlab)<0) {
        std::fprintf(stderr,"Python embedded module registration failed\n");
        return 1;
    }
    PyConfig config;
    PyConfig_InitPythonConfig(&config);
    config.parse_argv=0;
#ifdef _WIN32
    auto status=PyConfig_SetArgv(&config,argc,argv);
#else
    auto status=PyConfig_SetBytesArgv(&config,argc,argv);
#endif
    if(!PyStatus_Exception(status)) status=Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if(PyStatus_Exception(status)) {std::fprintf(stderr,"Python initialization failed: %s\n",status.err_msg?status.err_msg:"");return 1;}
    int result=0;
    auto* module=PyModule_New("hexlab");
    if(!module || PyDict_SetItemString(PyImport_GetModuleDict(),"hexlab",module)<0) result=1;
    if(!result) {
        auto* evaluated=PyRun_String(hexlab_python_facade,Py_file_input,PyModule_GetDict(module),PyModule_GetDict(module));
        if(!evaluated) result=1;
        Py_XDECREF(evaluated);
    }
    Py_XDECREF(module);
    if(result) PyErr_Print();
    else if(argc>1) {
        // runpy preserves Python file encoding, tracebacks, __file__, and argv.
        auto* sys=PyImport_ImportModule("sys");
        auto* arguments=sys?PyObject_GetAttrString(sys,"argv"):nullptr;
        auto* borrowed_script=arguments?PyList_GetItem(arguments,1):nullptr;
        auto* script=borrowed_script?Py_NewRef(borrowed_script):nullptr;
        if(!script || !arguments || PySequence_DelItem(arguments,0)<0) result=1;
        if(!result){
            auto* main=PyImport_AddModule("__main__");
            auto* prepared=main?PyRun_String("import os, sys\nsys.path.insert(0, os.path.dirname(os.path.abspath(sys.argv[0])))\n",Py_file_input,PyModule_GetDict(main),PyModule_GetDict(main)):nullptr;
            if(!prepared)result=1;Py_XDECREF(prepared);
        }
        auto* runpy=result?nullptr:PyImport_ImportModule("runpy");
        auto* run=runpy?PyObject_GetAttrString(runpy,"run_path"):nullptr;
        auto* name=PyUnicode_FromString("__main__");
        auto* args=script?PyTuple_Pack(1,script):nullptr;
        auto* kwargs=name?Py_BuildValue("{s:O}","run_name",name):nullptr;
        auto* executed=run&&args&&kwargs?PyObject_Call(run,args,kwargs):nullptr;
        if(!executed) {PyErr_Print();result=1;}
        Py_XDECREF(executed);Py_XDECREF(kwargs);Py_XDECREF(args);Py_XDECREF(name);
        Py_XDECREF(run);Py_XDECREF(runpy);Py_XDECREF(arguments);Py_XDECREF(sys);Py_XDECREF(script);
    } else {
        // Never pass a FILE* from HexLab's Debug CRT into release CPython.
        auto* evaluated=PyRun_String("import code\ncode.interact(banner='HexLab Python automation v1', local=globals())\n",Py_file_input,
            PyModule_GetDict(PyImport_AddModule("__main__")),PyModule_GetDict(PyImport_AddModule("__main__")));
        if(!evaluated){PyErr_Print();result=1;}Py_XDECREF(evaluated);
    }
    if(Py_FinalizeEx()<0)result=1;
    return result;
}
