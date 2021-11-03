#include <stdio.h>
#include <stdlib.h>


void unreachable(int b, int c) {
    printf("in unreachable: %d %d", b, c);
}

void indir(int b, char c) {
    printf("in indir: %d %d", b, c);
}

void indir2(int b, char c) {
    printf("in indir2: %d %d", b, c);
}

int my_malloc(int a, void (*f) (int, char)) {
    if (5 > a) {
        return a - 1;
    }
    f(a + 100, a + 10);
    printf("%d", a);
    return a;
}

int main(int argc, char** argv) {
    char inp[3];
    int num_read = 3;
    printf("%d", my_malloc(5, indir));
    fgets(inp, num_read, stdin);
    int size = atoi(inp);
    char tmp_size = 12;
    int* test = malloc(tmp_size);
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
