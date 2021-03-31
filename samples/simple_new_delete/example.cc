#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    char inp[3];
    fgets(inp, 3, stdin);
    int size = atoi(inp);
    printf("working on buffer of size %d\n", size);
    if (size == 0) {
        printf("not a valid size %d\n", size);
        return 0;
    }
    // Mutation: could reduce allocated size
    char* buffer = new char[size];
    for (int i = 0; i <= size - 1; i++) {
        buffer[i] = 'a';
    }
    buffer[size] = 65;
    printf("%c\n", buffer[size]);
    buffer[size-1] = 0;
    printf("%s\n", buffer);
    buffer[size-1] = 65;
    buffer[size] = 0;
    printf("%s\n", buffer);
    // Mutation: maybe also use the free() mutation here, even though it has shown to be pretty ineffective.
    // Mutation: Not sure if possible but this could be replaced with "delete[]", so a array deletion instead of object.
    delete[] buffer;
    return 0;
}
