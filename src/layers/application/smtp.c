// Global libraries
#include <stdlib.h>
#include <string.h>

// Local header files
#include "smtp.h"

const char *smtp_command[] = {"HELO", "MAIL", "RCPT", "DATA", "QUIT", "EHLO"};

static int is_command(const u_char *packet)
{
    for (int i = 0; i < 6; i++) {
        if (strncmp((char *)packet, smtp_command[i], strlen(smtp_command[i])) ==
            0) {
            return 1;
        }
    }
    return 0;
}

static int is_return_code(const u_char *packet)
{
    char buf[4];
    strncpy(buf, (char *)packet, 3);
    int code = atoi(buf);
    if ((code >= 200 && code <= 259) || (code >= 300 && code <= 359) ||
        (code >= 400 && code <= 459) || (code >= 500 && code <= 559)) {
        return 1;
    }
    return 0;
}

int is_smtp(const u_char *packet)
{
    if (is_command(packet)) {
        return 1;
    }
    else if (is_return_code(packet)) {
        return 1;
    }
    else {
        return 0;
    }
}