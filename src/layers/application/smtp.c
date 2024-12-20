/**
 * @author Flavien Lallemant
 * @file smtp.c
 * @brief SMTP Protocol Implementation File
 * @ingroup application
 * 
 * This file contains the implementation of the SMTP protocol.
 * 
 * @see smtp.h
 * @see is_smtp
 */

// Global libraries
#include <stdlib.h>
#include <string.h>

// Local header files
#include "smtp.h"

const char *smtp_command[] = {"HELO", "MAIL", "RCPT", "DATA", "QUIT", "EHLO"}; /**< List of SMTP commands */


/**
 * @brief Check if the packet is an SMTP command
 * 
 * @param packet The packet
 * @return int 1 if the packet is an SMTP command, 0 otherwise
 * 
 * @note This function doesn't check for errors.
 */
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


/**
 * @brief Check if the packet is an SMTP return code
 * 
 * @param packet The packet
 * @return int 1 if the packet is an SMTP return code, 0 otherwise
 * 
 * @note SMTP return codes are in the form of 3 digits. The first digit is between 2 and 5. The second digit is between 0 and 5. The last digit is between 0 and 9.
 */
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


/**
 * @brief Check if the packet is an SMTP packet
 * 
 * @param packet The packet
 * @return int 1 if the packet is an SMTP packet, 0 otherwise
 */
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