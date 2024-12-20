// Global libraries
#include <string.h>

// Local header files
#include "pop.h"

const char *pop_command[] = {"USER", "PASS", "STAT", "LIST", "UIDL", "RETR",
                             "DELE", "TOP",  "LAST", "RSET", "NOOP", "QUIT"};

const char *pop_response[] = {"+OK", "-ERR"};

static int is_command(const u_char *packet)
{
    for (int i = 0; i < 12; i++) {
        if (strncmp((char *)packet, pop_command[i], strlen(pop_command[i])) ==
            0) {
            return 1;
        }
    }
    return 0;
}

static int is_response(const u_char *packet)
{
    for (int i = 0; i < 2; i++) {
        if (strncmp((char *)packet, pop_response[i], strlen(pop_response[i])) ==
            0) {
            return 1;
        }
    }
    return 0;
}

int is_pop(const u_char *packet)
{
    // printf("DEBUG: %s\n", packet);
    if (is_command(packet)) {
        return 1;
    }
    else if(is_response(packet)) {
        return 1;
    }
    return 0;
}