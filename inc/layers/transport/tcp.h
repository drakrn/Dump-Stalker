/**
 * @author Flavien Lallemant
 * @file tcp.h
 * @brief TCP layer
 * @ingroup transport
 * 
 * This file contains the definition of the TCP layer.
 * It provides the function to handle TCP packets.
 */

#ifndef TCP_H
#define TCP_H

#if 0
/* Only to fix intellisense being dumb */
#define __USE_MISC 1
#endif

#include <netinet/tcp.h> 
#include "types.h"


/**
 * @brief Handle a TCP packet
 * 
 * This function handles a TCP packet.
 * 
 * @param packet The packet to handle
 * @param remain_size The remaining size of the packet
 * @return int 0 if the packet is well handled, -1 otherwise
 */
int cast_tcp(const u_char *packet, int remain_size);

#endif // TCP_H