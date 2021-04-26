//
// Created by Björn Mathis on 26.04.21.
//

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    char inp[3];
    fgets(inp, 3, stdin);
    int size = atoi(inp);
    int i = 0;
    for (; i < size && i < 10; i++) {
        printf("Value of i: %d\n", i);
    }
    printf("Finished, value of i: %d\n", i);
}