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
    char inp[5];
    fgets(inp, 5, stdin);
    int num = atoi(inp);

    struct Sample sample_stack = Sample { num, num+1 };
    // Mutation: It probably doesn't help to reduce the size of a individual struct but maybe we can do
    // something similar to uninitialized memory mutation where individual member fields are not initialized.
    struct Sample* sample_heap = new Sample { num, num+1 };

    std::cout << "sample stack: " << &sample_stack << "\n";
    print_sample(&sample_stack);

    std::cout << "sample heap: " << sample_heap << "\n";
    print_sample(sample_heap);

    delete sample_heap;

    return 0;
}
