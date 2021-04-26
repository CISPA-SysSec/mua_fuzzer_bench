//
// Created by Björn Mathis on 26.04.21.
//

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    char inp[3];
    fgets(inp, 3, stdin);
    int size = atoi(inp);
    int plus = 10 + size;
    int minus = 10 - size;
    double fplus = 10.0 + (double) size;
    double fminus = 10.0 - (double) size;
    printf("Plus: %d\nMinus: %d\nfPlus: %f\nfMinus: %f\n", plus, minus, fplus, fminus);
}