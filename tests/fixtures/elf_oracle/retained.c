__attribute__((noinline)) int target(void) { return 7; }
int _start(void) { return target(); }
