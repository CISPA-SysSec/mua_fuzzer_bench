#include <stdio.h>
#include <stdlib.h>

// adapted from: https://cwe.mitre.org/data/definitions/119.html
int main(int argc, char** argv) {
    // Get the input buffer
    #define MAX_SIZE 4
    char inp[MAX_SIZE];
    fgets(inp, MAX_SIZE, stdin);

    int i, dst_index;
    
    // Mutation: If the `MAX_EXPANSION_FACTOR` is not as large as the 
    // largest character expansion in this case "&" -> "&amp;" == 5
    // then a buffer overflow is possible.
    #define MAX_EXPANSION_FACTOR 5
    char *dst_buf = (char*)malloc((MAX_EXPANSION_FACTOR*sizeof(char) * MAX_SIZE) + 1);
    #undef MAX_EXPANSION_FACTOR
    #undef MAX_SIZE

    dst_index = 0;
    for ( i = 0; i < strlen(inp); i++ ){
        if( '&' == inp[i] ){
            /* encode to &amp; */
            dst_buf[dst_index++] = '&';
            dst_buf[dst_index++] = 'a';
            dst_buf[dst_index++] = 'm';
            dst_buf[dst_index++] = 'p';
            dst_buf[dst_index++] = ';';
        }
        else if ('<' == inp[i] ){
            /* encode to &lt; */
            dst_buf[dst_index++] = '&';
            dst_buf[dst_index++] = 'l';
            dst_buf[dst_index++] = 't';
            dst_buf[dst_index++] = ';';
        }
        else dst_buf[dst_index++] = inp[i];
    }
    printf("Encoded string %s", dst_buf);
}