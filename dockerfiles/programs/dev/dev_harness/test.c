#include <stdio.h>
#include <stddef.h>

__attribute__((noinline))
void do_something(unsigned char data) {
    int res = 0;
    if (data % 2) {
        res += 1;
    } else {
        res += 2;
    }

    printf("%d", res);
}

// Entrypoint for Clang's libfuzzer
int LLVMFuzzerTestOneInput(const unsigned char *data,
                           unsigned long size)
{
    if (size < 1)
    {
        return 0;
    }

    do_something(data[0]);

    return 0;
}
