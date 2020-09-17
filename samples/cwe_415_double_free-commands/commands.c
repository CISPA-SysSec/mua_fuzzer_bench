#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* skip_letters(char* inp);
char* double_letters(char* inp);


// Double all letters in the input.
char* double_letters(char* inp) {
    unsigned long len;

    len = strlen(inp);

    // If input len is zero, nothing to do.
    if (len == 0) return inp;

    // Need twice the space of input string plus null termintor.
    char* res = (char*)malloc(len*2+1);

    // Pointers to the buffers for easier manipulation.
    char* inpptr = inp;
    char* outptr = res;

    // Go through input string and copy every byte twice.
    for (unsigned long ii = 0; ii < len; ii++) {
        *outptr++ = *inpptr;
        *outptr++ = *inpptr++;
    }

    // Don't forget to zero terminate.
    *outptr = '\0';

    printf("%lu %lu %s\n", strlen(inp), strlen(res), res);

    // Mutation: inp is no longer needed and could be freed here,
    // which would cause a double free.

    return res;
}

// Skip every other letter in the input.
char* skip_letters(char* inp) {
    unsigned long len;

    len = strlen(inp);

    // If input len is zero, nothing to do.
    if (len == 0) return inp;

    // Pointers to the buffers for easier manipulation.
    char* inpptr = inp;
    char* outptr = inp;

    // Go through input string and skip every other byte, modifying
    // the original input buffer.
    for (unsigned long ii = 0; ii < len / 2; ii++) {
        *outptr++ = *inpptr++;
        inpptr++;
    }

    // Don't forget to zero terminate.
    *outptr = '\0';

    printf("%lu %lu %s\n", strlen(inp), strlen(inp), inp);

    return inp;
}


int main() {
    // Get the command to execute
    #define INP_SIZE 32
    char* command = (char*)malloc(INP_SIZE);
    char* commandptr = command;
    fgets(command, INP_SIZE, stdin);

    // Get the input to operate on
    char* inp = (char*)malloc(INP_SIZE);
    fgets(inp, INP_SIZE, stdin);

    // Temporary variable to allow store the result buffer, while freeing
    // the input buffer.
    char* tmp = NULL;

    // Go through the command input and apply the commands.
    while (*commandptr != '\0') {
        if        (*commandptr == 'd') {
            tmp = double_letters(inp);
        } else if (*commandptr == 's') {
            tmp = skip_letters(inp);
        }

        // If the input and tmp pointers are not equal a new buffer was
        // allocated, in that case free the original input buffer.
        if (tmp != NULL && tmp != inp) {
            free(inp);
            inp = tmp;
        }

        // Set tmp back to NULL, to avoid any unwanted accesses.
        tmp = NULL;
        // Mutation: (maybe not feasible) If tmp would not be set
        // to NULL it could be later freed, which would also mirror
        // some real world double frees.

        // Go to next command
        commandptr++;
    }

    printf("%s\n", inp);

    free(command);
    free(inp);
}
