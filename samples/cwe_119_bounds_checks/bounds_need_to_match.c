#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    char inp[10];
    int flag = 0;
    // Mutation: If the number of bytes read is larger than the buffer size,
    // this will lead to a buffer overflow.
    fgets(inp, 10, stdin);
    if (flag) {
        abort();
    }
    printf("Got: %s", inp);
}