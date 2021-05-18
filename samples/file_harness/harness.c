#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>

int LLVMFuzzerInitialize(int* argc, char*** argv);
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main(int argc, char** argv) {
    FILE *fp;
    int fd;
    size_t size;
    uint8_t *data;

    LLVMFuzzerInitialize(&argc, &argv);

    fp = fopen(argv[2], "r");
    if (fp == NULL) {
        perror("Could not open file\n.");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0L, SEEK_END);
    size = ftell(fp);

    fd = fileno(fp);
    data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == (uint8_t*)-1) {
        perror("Could not mmap file\n.");
        exit(EXIT_FAILURE);
    }

    /* Call function to be fuzzed, e.g.: */
    LLVMFuzzerTestOneInput(data, size);

    return 0;
}

