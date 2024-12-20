/**
 * @author Flavien Lallemant
 * @file http.c
 * @brief HTTP Protocol Implementation File
 * @ingroup application
 * 
 * This file contains the implementation of the HTTP layer.
 * 
 * @see http.h
 * @see is_http
 */

// Global libraries
#include <string.h>

// Local header files
#include "http.h"

const char *http_command[] = {"GET", "POST",    "HEAD",
                              "PUT", "OPTIONS", "CONNECT"}; /**< List of HTTP commands */
const char *http_response[] = {"HTTP/1.1", "HTTP/2", "HTTP/3"}; /**< List of HTTP responses */


/**
 * @brief Check if a packet is an HTTP command
 * 
 * @param packet The packet to check
 * @return 1 if the packet is an HTTP command, 0 otherwise
 * 
 * @note This function doesn't check for errors.
 */
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


/**
 * @brief Check if a packet is an HTTP response
 * 
 * @param packet The packet to check
 * @return 1 if the packet is an HTTP response, 0 otherwise
 * 
 * @note This function doesn't check for errors.
 */
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

/**
 * @brief Check if a packet is an HTTP packet
 * 
 * @param packet The packet to check
 * @return 1 if the packet is an HTTP packet, 0 otherwise
 */
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