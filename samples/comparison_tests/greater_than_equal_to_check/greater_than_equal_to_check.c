#include <stdio.h>

struct testStruct {
    int testvar1;
    int testvar2;
};
int main() {
    int intarray[2] = {20, 21};
    int *ptra, *ptrb;
    ptra = &intarray[0];
    ptrb = ptra+1;

    //integer check
    printf("Testing for integers.\n");
    printf ("intarray[0]: %d, intarray[1]: %d.\n", intarray[0], intarray[1]);
    if (intarray[0] >= intarray[1]){
        printf ("intarray[0] >= intarray[1]. Mutated execution.\n\n");
    }
    else {
        printf ("intarray[0] is not >= intarray[1]. Normal execution.\n\n");
    }

    //pointer check in an array
    printf("Testing for pointers in an array. If mutated, while loop runs 10 times instead of just 2 times.\n");
    printf("ptrb:%p ptra:%p\n", ptra, ptrb);
    printf("Entering while loop now.\n");
    while(ptrb >= ptra){
        printf ("*ptrb: %d, ptrb: %p, ptra: %p\n", *ptrb, ptrb, ptra);
        ptrb--;
    }
    struct testStruct ts;
    ptra = &(ts.testvar1);
    ptrb = &(ts.testvar2);
    //pointer check in a struct
    printf("\nTesting for pointers in a struct. If mutated, while loop runs 10 times instead of just 2 times.\n");
    // printf("ptra:%p ptrb:%p\n", ptra, ptrb);
    printf("Entering while loop now.\n");
    while(ptrb >= ptra){
        printf ("*ptrb: %d, ptrb: %p, ptra: %p\n", *ptrb, ptrb, ptra);
        ptrb--;
    }

    return 0;
}