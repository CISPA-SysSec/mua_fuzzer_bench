#include <stdio.h>

int main() {
    int a, b;
    int *ptra, *ptrb;
    a=57;
    b=21;
    ptra = &a;
    ptrb = &b;
    if (a == b){
        printf("a is equal to b. This will be triggered after mutation.\n");
    }
    else{
        printf("a is not equal to b. This will be triggered by default.\n");
    }
    a=0;
    if (a==0){
        printf("a is equal to 0. This will be triggered by default.\n");
    }
    else{
        printf("a is not equal to 0. This will be triggered after mutation.\n");
    }

    if (ptra == ptrb){
        printf("ptra and ptrb point to the same integer. This will be triggered after mutation.\n");
    }
    else{
        printf("ptra and ptrb do not point to the same integer. This will be triggered by default.\n");
    }

    ptra = NULL;

    if (ptra == NULL){
        printf("ptra points to NULL. This will be triggered by default.\n");
    }
    else{
        printf("ptra doesn't point to NULL. This will be triggered after mutation.\n");
    }

    return 0;
}