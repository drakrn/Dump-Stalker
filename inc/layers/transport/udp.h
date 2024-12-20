/**
 * @author Flavien Lallemant
 * @file udp.h
 * @brief UDP layer
 * @ingroup transport
 * 
 * This file contains the definition of the UDP layer.
 * It provides the function to handle UDP packets.
 */
#ifndef UDP_H
#define UDP_H

#include <netinet/udp.h>
#include "types.h"


/**
 * @brief Handle a UDP packet
 * 
 * This function handles a UDP packet.
 * 
 * @param packet The packet to handle
 * @return int 0 if the packet is well handled, -1 otherwise
 */
int cast_udp(const u_char* packet);

#endif // UDP_H