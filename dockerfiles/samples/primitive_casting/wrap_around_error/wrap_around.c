#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INP_SIZE 1024

struct work {
    char the_input;
    char more_data[63];
};

int main() {
    char inp[INP_SIZE];
    fgets(inp, INP_SIZE, stdin);
    // Mutation: Changing the type of inp_size from unsigned long to unsigned
    // char, obviously an exteme example, will result in OOB writes, as malloc
    // will not allocate enough memory. Different kinds of casts are interesting,
    // in this case the reduction of bitlength of the primitive.
    // Other examples would be casting from long to int or long long to int and
    // so on... The same for the types of "stdint.h" (uint32_t, int64_t, ...).
    unsigned long inp_size = strlen(inp);

    // Allocate buffer to copy to.
    // TODO truncate bitlength of input to add/sub/mul/fmul ...
    struct work* data = (struct work*) malloc(inp_size*sizeof(struct work));
    if (data == NULL) {
        return 1;
    }

    // Set pointers to use during copying.
    char* cur_inp = inp;
    struct work* cur_data = data;

    // Copy the data.
    while (*cur_inp != 0) {
        cur_data->the_input = *cur_inp;
        cur_data += 1;
        cur_inp += 1;
    }

    // Free work data.
    free(data);

    return 0;
}
