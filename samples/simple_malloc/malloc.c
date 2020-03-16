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
    char* buffer2 = malloc(sizeof(char) * size * 2);
    char* buffer3 = malloc(sizeof(char) * size * 2);
    char* buffer4 = malloc(sizeof(char) * size * 2);
    char* buffer5 = malloc(sizeof(char) * size * 2);
    char* buffer6 = malloc(sizeof(char) * size * 2);
    char* buffer7 = malloc(sizeof(char) * size * 2);
    char* buffer8 = malloc(sizeof(char) * size * 2);
    char* buffer9 = malloc(sizeof(char) * size * 2);
    for (int i = 0; i < size * 2; i++) {
        buffer2[i] = 'b';
    }
    return 0;
}