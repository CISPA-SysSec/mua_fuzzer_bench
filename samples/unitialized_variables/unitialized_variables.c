#include <stdio.h>
#include <stdlib.h>

#define INP_SIZE 4

// based on: https://cwe.mitre.org/data/definitions/457.html (Example 2)
int main() {
    char inp[INP_SIZE] = {0};
    int aN, bN, ctl, ii;
    while (1) {
        fgets(inp, INP_SIZE, stdin);
        ctl = atoi(inp);
        switch (ctl) {
            case 1:
                aN = 0;
                bN = 0;
                break;

            case 2:
                aN += 1;
                bN -= 1;
                break;

            case 3:
                aN *= 2;
                bN *= 2;
                break;

            default:
                aN = -1;
                // Mutation: In the example this would also set aN to -1,
                // leaving `bN` unitialized. This could be done wherever, not
                // sure how to limit the amount of mutations.
                // TODO delete constant assignment
                bN = -1;
                break;
        }
        printf("%d %d\n", aN, bN);
    }
}