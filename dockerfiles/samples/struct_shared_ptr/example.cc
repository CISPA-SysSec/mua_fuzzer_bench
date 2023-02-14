#include <stdio.h>
#include <iostream>
#include <memory>

struct Sample {
    int num;
    int more_num;
};

__attribute__((noinline))
void print_sample(std::shared_ptr<struct Sample> sample) {
    std::cout << "Sample num: " << sample->num << " more_num: " << sample->more_num << "\n";
}

int main() {
    char inp[5];
    fgets(inp, 5, stdin);
    int num = atoi(inp);

    {
        std::shared_ptr<struct Sample> sample1(new Sample { num, num+2 });
        {
            auto sample2(sample1);
            std::cout << "sample2: " << sample2.get() << " refs: " << sample2.use_count() << "\n";
            print_sample(sample2);
            sample2->more_num += 1;
        }
        std::cout << "sample1: " << sample1.get() << " refs: " << sample1.use_count() << "\n";
        print_sample(sample1);
        // Mutation: The sample object should be freed here, maybe free earlier or something similar to free() mutation.
    }

    std::cout << "done\n";

    return 0;
}
