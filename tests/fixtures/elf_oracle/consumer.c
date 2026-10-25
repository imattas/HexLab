extern int external_call(int);
static int local_data = 7;
int exported_function(int value) { return external_call(value) + local_data; }
int zero_storage[16];
