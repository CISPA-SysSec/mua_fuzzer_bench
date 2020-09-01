#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// adapted from: https://cwe.mitre.org/data/definitions/119.html
int main(int argc, char** argv) {
    // Get the input
    #define MAX_SIZE 32
    char inp[MAX_SIZE];
    fgets(inp, MAX_SIZE, stdin);

    char *items[] = {"boat", "car", "truck", "train"};
    int index = atoi(inp);

    // Mutation: removing the bounds checks (upper or lower) will enable out
    // of bounds reads.
    if (index > 0 && index <= 4) {
        printf("You selected %s\n", items[index-1]);
    }

    #undef MAX_SIZE
}