/**
 * @author Flavien Lallemant
 * @file telnet.c
 * @brief Telnet Protocol Implementation File
 * @ingroup application
 * 
 * This file contains the implementation of the Telnet layer.
 * 
 * @see telnet.h
 * @see telnet_handler
 * 
 * @note NOT IMPLEMENTED YET.
 */

// Global libraries
#include <stdio.h>

// Local header files
#include "telnet.h"

/**
 * @brief Handle a Telnet packet
 * 
 * This function handles a Telnet packet.
 * 
 * @param packet The packet to handle
 * @return int 0 if the packet is well handled, -1 otherwise
 */
int telnet_handler(const u_char *packet) {
    if (packet) {
        ;
    }
    printf("No handling yet\n");
    return 0;
}