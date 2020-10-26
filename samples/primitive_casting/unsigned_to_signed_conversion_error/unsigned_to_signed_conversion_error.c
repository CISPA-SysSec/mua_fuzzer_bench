#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INP_SIZE 1024

// Based on: https://cwe.mitre.org/data/definitions/196.html

// Mutation: Change the argument type to `int`, this will cause the shift to be
// a arithmetic shift instead of a logical, thus shifting in the sign bit.
// This mutation can be done for return types, argument types and variable types,
// maybe also in structs or unions.
static unsigned int shift_right(unsigned int val) {
    return val >> 2;
}

int main() {
    char inp[INP_SIZE];
    fgets(inp, INP_SIZE, stdin);

    int result = atoi(inp);

    printf("Got number: %d\n", shift_right((unsigned int) result));
    return 0;
}
