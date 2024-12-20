/**
 * @author Flavien Lallemant
 * @file icmp.h
 * @brief ICMP layer
 * @ingroup network
 * 
 * This file contains the definition of the ICMP layer.
 * It provides the function to handle ICMP packets.
 */

#ifndef ICMP_H
#define ICMP_H

#include <netinet/ip_icmp.h>
#include "types.h"

/**
 * @brief ICMP type
 * @note This list completes the list of ICMP types defined in <netinet/ip_icmp.h>
 */
#define ICMP_ROUTER_ADVERT 9
#define ICMP_ROUTER_SOLICIT 10
#define ICMP_TRACEROUTE 30


/**
 * @brief Handle an ICMP packet
 * 
 * This function handles an ICMP packet.
 * 
 * @param packet The packet to handle
 * @return int 0 if the packet is well handled, -1 otherwise
 */
int cast_icmp(const u_char *packet);

#endif // ICMP_H