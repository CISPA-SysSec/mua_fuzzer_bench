#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    char inp[3];
    fgets(inp, 3, stdin);
    int size = atoi(inp);
    char* buffer = malloc(sizeof(char) * size);
    for (int i = 0; i < size; i++) {
        buffer[i] = 'a';
    }
    return 0;
}