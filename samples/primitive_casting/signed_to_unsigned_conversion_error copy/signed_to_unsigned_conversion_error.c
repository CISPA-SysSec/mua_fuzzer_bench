#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INP_SIZE 1024

// Based on: https://cwe.mitre.org/data/definitions/195.html

// Mutation: Change the return type to `unsigned int`.
// This mutation can be done for return types, argument types and variable types,
// maybe also in structs or unions.
// For example during parsing a length field of an incoming packet, if that is
// interpreted as a signed value, then there could be a negative length which
// could have uninteded consequences.
static int parse_inp_number(char* inp) {
    int result = atoi(inp);
    if (result < 0) {
        return -1;
    } else {
        return result;
    }
}

int main() {
    char inp[INP_SIZE];
    fgets(inp, INP_SIZE, stdin);

    // Mutation: Change the type of this variable to `unsigned int`.
    int result = parse_inp_number(inp);
    if (result < 0) {
        printf("%s\n", "Invalid number.");
        return 0;
    }

    printf("Got number: %d\n", result);
    return 0;
}
