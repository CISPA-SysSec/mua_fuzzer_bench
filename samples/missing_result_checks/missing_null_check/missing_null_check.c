#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define INP_SIZE 1024

// Based on: https://cwe.mitre.org/data/definitions/476.html

// Not sure what the best / most generic way to implement these mutations is.
// Naively maybe just remove the the comparison if it is against a static value.
// It may be more difficult with compound conditions like:
// (addr < 0 && size > 50)

static void host_lookup(char *user_supplied_addr) {
    struct hostent *hp;
    in_addr_t addr;
    char hostname[64];
    in_addr_t inet_addr(const char *cp);

    /*routine that ensures user_supplied_addr is in the right format for conversion */

    addr = inet_addr(user_supplied_addr);
    printf("addr: %d\n", addr);

    // Mutation: Removing this check that addr can not be equal to -1.
    if (addr == (unsigned int)-1) {
        printf("%s: '%s'\n", "Could not convert the address", user_supplied_addr);
        return;
    }
    
    hp = gethostbyaddr(&addr, sizeof(struct in_addr), AF_INET);

    // Mutation: Removing this check that hp can not be equal to NULL.
    if (hp == NULL) {
        printf("%s: '%s'\n", "Could not find the address", user_supplied_addr);
        return;
    }

    strncpy(hostname, hp->h_name, 64);
    printf("%s: '%s' -> '%s'\n", "Found address", user_supplied_addr, hostname);
}

int main() {
    char inp[INP_SIZE];
    fgets(inp, INP_SIZE, stdin);

    host_lookup(inp);

    return 0;
}
