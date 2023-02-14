#include <stdio.h>
#include <iostream>

struct Sample {
    int num;
    int more_num;
};

__attribute__((noinline))
void print_sample(struct Sample* sample) {
    std::cout << "Sample num: " << sample->num << " more_num: " << sample->more_num << "\n";
}

int main(int argc, char** argv) {
    const int ARR_SIZE = 10;
    char inp[5];
    fgets(inp, 5, stdin);
    int num = atoi(inp);

    // Mutation: Once more a memory allocation where size could be reduced.
    struct Sample *sample_heap = new Sample[ARR_SIZE];

    for (int ii = 0; ii < ARR_SIZE; ii++) {
        sample_heap[ii] = Sample { num, num+ii };
    }

    for (int ii = 0; ii < ARR_SIZE; ii++) {
        std::cout << "sample heap: " << &sample_heap[ii] << "\n";
        print_sample(&sample_heap[ii]);
    }

    // Mutation: Not sure if possible but this could be replaced with "delete", so a object deletion instead of array.
    delete[] sample_heap;

    return 0;
}
