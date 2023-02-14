#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INP_SIZE 1024

// Based on: https://cwe.mitre.org/data/definitions/134.html

// Interesting functions:
// https://man7.org/linux/man-pages/man3/printf.3.html

static void do_a(char* inp) {
    // Mutation: Either just replace the first arg with inp, or replace the %s
    // with the inp arg and use the result as the first argument.
    printf("a: %s\n", inp);
    char testbuf[500];
    snprintf(testbuf, 10L,  "a: %s", "test");
}

static void do_b(char* inp) {
    // Mutation: Same as above, however more arguments. Maybe the most generic
    // way to implement this is to use sprintf to get the new string and then
    // use that as the first argument.
    printf("b: %d %s %d\n", 5, inp, 6);
    // Above line could be transformed to:
    //    char * fmt_str = malloc(1024);
    // Create the new format string.
    //    snprintf(fmt_str, 1024, <Copy of the original printf>, <args to printf>);
    // Use the new format string.
    //    printf(fmt_str);
}

int main() {
    char inp[INP_SIZE];
    fgets(inp, INP_SIZE, stdin);

    do_a(inp);
    do_b(inp);

    return 0;
}
