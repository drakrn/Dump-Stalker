/**
 * @author Flavien Lallemant
 * @file ipv6.h
 * @brief IPv6 layer
 * @ingroup network
 * 
 * This file contains the definition of the IPv6 layer.
 * It provides the function to handle IPv6 packets.
 */

#ifndef IPv6_H
#define IPv6_H

#include <netinet/ip6.h>
#include <linux/in6.h>
#include <arpa/inet.h>
#include "types.h"


/**
 * @brief Handle an IPv6 packet
 * 
 * This function handles an IPv6 packet.
 * 
 * @param packet The packet to handle
 * @return int 0 if the packet is well handled, -1 otherwise
 */
int cast_ipv6(const u_char* packet);

#endif  // IPv6_H