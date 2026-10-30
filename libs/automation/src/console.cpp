#include "python_internal.hpp"
#include "facade.hpp"
#include <cstdio>
#include <cstring>
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
        // Match the useful script-running modes of Python while keeping the
        // embedded interpreter's command line out of Python's own option parser.
        auto* sys=PyImport_ImportModule("sys");
        auto* arguments=sys?PyObject_GetAttrString(sys,"argv"):nullptr;
        auto* first=arguments?PyList_GetItem(arguments,1):nullptr;
        const auto* mode=first&&PyUnicode_Check(first)?PyUnicode_AsUTF8(first):nullptr;
        if(!arguments || !mode) result=1;
        else if(std::strcmp(mode,"--help")==0 || std::strcmp(mode,"-h")==0) {
            std::fputs("Usage: hexlab_python [script.py [arguments...]]\n       hexlab_python -c command [arguments...]\n       hexlab_python -m module [arguments...]\n       hexlab_python\n",stdout);
        } else if(std::strcmp(mode,"-c")==0 || std::strcmp(mode,"-m")==0) {
            const bool command_mode=std::strcmp(mode,"-c")==0;
            auto* operand=PyList_Size(arguments)>2?PyList_GetItem(arguments,2):nullptr;
            auto* payload=operand?Py_NewRef(operand):nullptr;
            auto* remainder=PyList_GetSlice(arguments,3,PyList_Size(arguments));
            if(!payload) PyErr_SetString(PyExc_ValueError,std::strcmp(mode,"-c")==0?"-c requires a command":"-m requires a module name");
            if(!payload || !remainder || PyList_SetSlice(arguments,0,PyList_Size(arguments),remainder)<0) result=1;
            if(!result) {
                auto* marker=command_mode?PyUnicode_FromString("-c"):Py_NewRef(payload);
                if(!marker || PyList_Insert(arguments,0,marker)<0) result=1;
                Py_XDECREF(marker);
            }
            auto* main=result?nullptr:PyImport_AddModule("__main__");
            auto* globals=main?PyModule_GetDict(main):nullptr;
            auto* prepared=globals?PyRun_String("import os, sys\nsys.path.insert(0, os.getcwd())\n",Py_file_input,globals,globals):nullptr;
            if(!prepared) result=1; Py_XDECREF(prepared);
            PyObject* executed=nullptr;
            if(!result && command_mode) {
                const auto* source=PyUnicode_AsUTF8(payload);
                executed=source?PyRun_String(source,Py_file_input,globals,globals):nullptr;
            } else if(!result) {
                auto* runpy=PyImport_ImportModule("runpy");
                auto* run=runpy?PyObject_GetAttrString(runpy,"run_module"):nullptr;
                auto* run_name=PyUnicode_FromString("__main__");
                auto* args=PyTuple_Pack(1,payload);
                auto* kwargs=run_name?Py_BuildValue("{s:O,s:O}","run_name",run_name,"alter_sys",Py_True):nullptr;
                executed=run&&args&&kwargs?PyObject_Call(run,args,kwargs):nullptr;
                Py_XDECREF(kwargs);Py_XDECREF(args);Py_XDECREF(run_name);Py_XDECREF(run);Py_XDECREF(runpy);
            }
            if(!result && !executed) {PyErr_Print();result=1;}
            Py_XDECREF(executed);Py_XDECREF(remainder);Py_XDECREF(payload);
        } else {
            // runpy preserves Python file encoding, tracebacks, __file__, and argv.
            auto* borrowed_script=PyList_GetItem(arguments,1);
            auto* script=borrowed_script?Py_NewRef(borrowed_script):nullptr;
            if(!script || PySequence_DelItem(arguments,0)<0) result=1;
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
            Py_XDECREF(run);Py_XDECREF(runpy);Py_XDECREF(script);
        }
        Py_XDECREF(arguments);Py_XDECREF(sys);
    } else {
        // Never pass a FILE* from HexLab's Debug CRT into release CPython.
        auto* evaluated=PyRun_String("import code\ncode.interact(banner='HexLab Python automation v1', local=globals())\n",Py_file_input,
            PyModule_GetDict(PyImport_AddModule("__main__")),PyModule_GetDict(PyImport_AddModule("__main__")));
        if(!evaluated){PyErr_Print();result=1;}Py_XDECREF(evaluated);
    }
    if(result && PyErr_Occurred()) PyErr_Print();
    if(Py_FinalizeEx()<0)result=1;
    return result;
}
