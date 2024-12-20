// Global libraries
#include <string.h>

// Local header files
#include "http.h"

const char *http_command[] = {"GET", "POST",    "HEAD",
                              "PUT", "OPTIONS", "CONNECT"};
const char *http_response[] = {"HTTP/1.1", "HTTP/2", "HTTP/3"};

static int is_command(const u_char *packet)
{
    for (int i = 0; i < 6; i++) {
        if (strncmp((char *)packet, http_command[i], strlen(http_command[i])) ==
            0) {
            return 1;
        }
    }
    return 0;
}

static int is_response(const u_char *packet)
{
    for (int i = 0; i < 3; i++) {
        if (strncmp((char *)packet, http_response[i],
                    strlen(http_response[i])) == 0) {
            return 1;
        }
    }
    return 0;
}

int is_http(const u_char *packet)
{
    if (is_command(packet)) {
        return 1;
    }
    else if (is_response(packet)) {
        return 1;
    }
    else {
        return 0;
    }
}