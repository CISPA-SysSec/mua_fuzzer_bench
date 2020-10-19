#include <stdio.h>
#include <stdlib.h>

#define INP_SIZE 32

struct person {
    char name[INP_SIZE];
    int id;
};

int main() {
    // Mutation: A typical mistake is to not specify `struct person` but instead
    // `sizeof(struct person*)` or equivalently `sizeof(person)`,
    // which would be too small for the actual struct.
    struct person* person = (struct person*)calloc(1, sizeof(struct person));

    // Mutation: Another mistake is forget to access the name field in the
    // and write `sizeof(person)` instead of `sizeof(person->name)`.
    // Another is dereferencing the field as in `sizeof(*person->name)`.
    fgets(person->name, sizeof(person->name), stdin);

    __builtin_dump_struct(person, &printf);
}