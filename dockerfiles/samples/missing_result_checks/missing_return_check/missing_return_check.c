#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define INP_SIZE 1024

// Based on: https://cwe.mitre.org/data/definitions/253.html

// Not sure what the best / most generic way to implement these mutations is.

int main() {
    char inp[INP_SIZE];
    fgets(inp, INP_SIZE, stdin);
    char *tmp;

    tmp = malloc(64);
    if (tmp == 0) {
        perror("Failed to allocate buffer.");
    }

    free(tmp);

    return 0;
}
