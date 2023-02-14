#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INP_SIZE 1024


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

    switch (inp_len) {
        case 1:
            do_x(inp);
            // Mutation: Remove break statements for cases in the switch.
            // Based on: https://cwe.mitre.org/data/definitions/484.html
            break;
        case 2:
            do_y(inp);
            break;
        // Mutation: Remove the default case for a switch.
        // https://cwe.mitre.org/data/definitions/478.html
        default:
            do_z(inp);
    }

    return 0;
}
