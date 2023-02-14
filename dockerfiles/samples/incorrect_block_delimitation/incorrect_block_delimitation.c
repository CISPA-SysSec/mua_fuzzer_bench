#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INP_SIZE 1024

// Based on: https://cwe.mitre.org/data/definitions/483.html

static void do_x(char* inp) {
    printf("x: %s\n", inp);
}

static void do_y(char* inp) {
    printf("y: %s\n", inp);
}

static void do_z(char* inp) {
    printf("z: %s\n", inp);
}

int main() {
    char inp[INP_SIZE];
    fgets(inp, INP_SIZE, stdin);

    unsigned long inp_len = strlen(inp);

    // Mutation: Remove the braces after this if statement. This will result in
    // `do_y` to be executed unconditionally. Since we are operating on llvm ir
    // this mutation is not straightforward and may be too difficult to achieve.
    if (inp_len > 2) {
        do_x(inp);
        do_y(inp);
    }

    do_z(inp);

    return 0;
}
