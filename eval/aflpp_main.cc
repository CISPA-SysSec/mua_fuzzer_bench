#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

__AFL_FUZZ_INIT();

int main() {

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {

        int len = __AFL_FUZZ_TESTCASE_LEN;

        LLVMFuzzerTestOneInput(buf, len);
    }

    return 0;
}