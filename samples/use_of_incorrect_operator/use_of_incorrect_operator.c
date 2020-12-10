#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INP_SIZE 1024

// Based on: https://cwe.mitre.org/data/definitions/480.html

// Not sure how realistic this mutation is but here we are, I would expect this
// to be detected even by happy path tests (nevermind that the compiler also
// detects these).

#define SIZE 50
static int *tos, *p1, stack[SIZE];

static void push(int i) {
    p1++;
    if(p1==(tos+SIZE)) {
        // Print stack overflow error message and exit
        fprintf(stderr, "Stack full");
        exit(1);
    }
    // Mutation: Should be changed into *p1 == i;
    *p1 = i;
}

static int pop(void) {
    // Mutation: Should be changed to if(p1 = tos)
    if(p1==tos) {
        // Print stack underflow error message and exit
        fprintf(stderr, "Stack underflow");
        exit(1);
    }

    p1--;
    return *(p1+1);
}

int main() {
    char inp[INP_SIZE] = { 0 };
    fgets(inp, INP_SIZE, stdin);
    int idx = 0;

    // initialize tos and p1 to point to the top of stack
    tos = stack;
    p1 = stack;

    // code to add and remove items from stack
    while (inp[idx] != 0) {
        if (inp[idx] >= 'a') {
            push(inp[idx]);
        } else {
            printf("%c", pop());
        }
        idx += 1;
    }

    printf("\n");

    return 0;
}
