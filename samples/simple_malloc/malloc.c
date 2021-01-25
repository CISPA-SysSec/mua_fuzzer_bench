#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    char inp[3];
    fgets(inp, 3, stdin);
    int size = atoi(inp);
    char* buffer = malloc(sizeof(char) * size);
    for (int i = 0; i <= size - 1; i++) {
        printf("%d\n", i);
        buffer[i] = 'a';
    }
    buffer[size] = 65;
    printf("%c\n", buffer[size]);
    buffer[size-1] = 0;
    printf("%s\n", buffer);
    buffer[size-1] = 65;
    buffer[size] = 0;
    printf("%s\n", buffer);
    free(buffer);
    return 0;
}