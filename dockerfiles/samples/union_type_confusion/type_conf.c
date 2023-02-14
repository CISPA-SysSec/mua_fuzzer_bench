#include <stdlib.h>
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

typedef struct{
    int a;
} test1;

typedef struct {
    char* b;
} test2 ;

typedef union {
    test1 a;
    test2 b;
} uni;

typedef struct{
    int hdr; //header identifies the union variant stored in dat
    uni dat
} pack;

pack get_package(int type, int val){
    if(type == 1){
        pack a = {.hdr=type, .dat = {.a= {.a=val} } };
        return a;
    }
    if(type == 2){
        char* str=NULL;
        asprintf(&str, "%d",val);
        pack a = {.hdr=type, .dat = {.b= {.b=str} } };
        return a;
    }
    printf("invalid type\n");
    exit(1);
}

int convert_package(pack* self){
    if(self->hdr == 1){
        self->hdr = 2; //hdr is set too early
        if(self->dat.a.a < 0){
            //error, cant convert negative numbers -> hdr is wrong, the variant is still type 1, while the header says 2
            return -1;
        }
        char* str=NULL;
        asprintf(&str, "%d",self->dat.a.a);
        self->dat.b.b = str;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int input = 1;
    scanf("%d", &input);
    pack a = get_package(1, input);
    convert_package(&a); //a now has hdr type 2, but if input<0 .dat is still an instance of struct1
    //Note this bug is trivial, and basically equivalent to assert(input >= 0); In reality one would typically need to trigger at least a specific path to a vulnerable target site after corrupting the struct
    printf("got pack: %s",a.dat.b.b);
    return 0;
}
