#pragma once
#include <exception>
#include <iostream>
#include <stdexcept>
#if defined(_MSC_VER)
#include <cstdlib>
#include <crtdbg.h>
#endif

namespace hexlab_test {
inline int failures = 0;
inline int checks = 0;
inline void check(bool success, const char* name) {
    ++checks;
    if (!success) { ++failures; std::cerr << "FAIL: " << name << '\n'; }
}
template<class F> void logic_error(F action, const char* name) {
    bool caught = false;
    try { action(); } catch (const std::logic_error&) { caught = true; }
    check(caught, name);
}
template<class F> int run(F action) {
#if defined(_MSC_VER)
    // Native assertion failures must fail the test process, not wait for a
    // modal CRT dialog on an unattended test desktop.
    _set_error_mode(_OUT_TO_STDERR);
    _set_abort_behavior(0,_WRITE_ABORT_MSG|_CALL_REPORTFAULT);
#if defined(_DEBUG)
    _CrtSetReportMode(_CRT_ASSERT,_CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT,_CRTDBG_FILE_STDERR);
#endif
#endif
    try { action(); }
    catch (const std::exception& e) { ++failures; std::cerr << "Unexpected exception: " << e.what() << '\n'; }
    std::cout << checks << " checks, " << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
}
