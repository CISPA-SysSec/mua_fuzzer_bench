#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    char inp[3];
    fgets(inp, 3, stdin);
    int size = atoi(inp);
    char* buffer = malloc(sizeof(char) * size);
    char* buffer2 = malloc(sizeof(char) * size);
    for (int i = 0; i <= size - 1; i++) {
        printf("%d\n", i);
        buffer[i] = 'a';
    }
    buffer[size] = 65;
    buffer2[size] = 66;
    int result = printf("%c\n", buffer[size]);
    printf("%d\n", result);
    buffer[size-1] = 0;
    result = sprintf(buffer2, "%s\n", buffer);
    printf("%d\n", result);
    result = snprintf(buffer2, size, "%s\n", buffer);
    printf("%d\n", result);
    buffer[size-1] = 65;
    buffer[size] = 0;
    printf("%s\n", buffer);
    free(buffer);
    return 0;
}