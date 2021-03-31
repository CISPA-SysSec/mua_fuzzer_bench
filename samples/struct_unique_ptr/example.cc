#include <stdio.h>
#include <iostream>
#include <memory>

using std::unique_ptr;

struct Sample {
    int num;
    int more_num;
};

__attribute__((noinline))
void print_sample(std::unique_ptr<struct Sample> sample) {
    std::cout << "Sample num: " << sample->num << " more_num: " << sample->more_num << "\n";
}

int main(int argc, char** argv) {
    char inp[5];
    fgets(inp, 5, stdin);
    int num = atoi(inp);

    unique_ptr<struct Sample> sample (new Sample { num, num+1 });

    std::cout << "sample: " << sample.get() << "\n";
    // Mutation: sample is nullptr after move, maybe we can somehow remove the move (for example copy the pointer)
    // to make the ptr not behave as a unique_ptr anymore.
    print_sample(std::move(sample));
    std::cout << "sample: " << sample.get() << "\n";
    // This would case a segmentation fault but C++ type system does not warn of this call.
    // print_sample(std::move(sample));

    std::cout << "done!\n";

    return 0;
}
