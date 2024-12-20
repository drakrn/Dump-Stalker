/**
 * @author Flavien Lallemant
 * @file pop.c
 * @brief POP Protocol Implementation File
 * @ingroup application
 * 
 * This file contains the implementation of the POP layer.
 * 
 * @see pop.h
 * @see is_pop
 */

// Global libraries
#include <string.h>

// Local header files
#include "pop.h"

const char *pop_command[] = {"USER", "PASS", "STAT", "LIST", "UIDL", "RETR",
                             "DELE", "TOP",  "LAST", "RSET", "NOOP", "QUIT"}; /**< List of POP commands */

const char *pop_response[] = {"+OK", "-ERR"}; /**< List of POP responses */


/**
 * @brief Check if the packet is a POP command
 * 
 * @param packet The packet
 * @return int 1 if the packet is a POP command, 0 otherwise
 * 
 * @note This function doesn't check for errors.
 */
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

/**
 * @brief Check if the packet is a POP response
 * 
 * @param packet The packet
 * @return int 1 if the packet is a POP response, 0 otherwise
 * 
 * @note This function doesn't check for errors.
 */
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


/**
 * @brief Check if a packet is a POP packet
 * 
 * @param packet The packet to check
 * @return 1 if the packet is a POP packet, 0 otherwise
 */
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