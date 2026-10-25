extern int external_function(int);
extern int imported_value;
static int local_value = 7;
int *local_pointer = &local_value;
int *external_pointer = &imported_value;
__attribute__((weak)) int weak_function(int value) { return value - 1; }
int (*weak_pointer)(int) = weak_function;
int entry(int value) { return external_function(value) + imported_value + local_value; }
