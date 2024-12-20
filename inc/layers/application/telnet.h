/**
 * @author Flavien Lallemant
 * @file telnet.h
 * @brief Telnet layer
 * @ingroup application
 * 
 * This file contains the definition of the Telnet layer.
 * It provides the function to handle Telnet packets.
 */

#ifndef TELNET_H
#define TELNET_H

#include "types.h"


/**
 * @brief Handle a Telnet packet
 * 
 * This function handles a Telnet packet.
 * 
 * @param packet The packet to handle
 * @return int 0 if the packet is well handled, -1 otherwise
 */
int telnet_handler(const u_char *packet);

#endif // TELNET_H