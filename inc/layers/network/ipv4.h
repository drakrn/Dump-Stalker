/**
 * @author Flavien Lallemant
 * @file ipv4.h
 * @brief IPv4 layer
 * @ingroup network
 * 
 * This file contains the definition of the IPv4 layer.
 * It provides the function to handle IPv4 packets.
 */

#ifndef IPv4_H
#define IPv4_H

#include <netinet/ip.h>
#include <linux/in.h>
#include <arpa/inet.h>
#include "types.h"


/**
 * @brief Handle an IPv4 packet
 * 
 * This function handles an IPv4 packet.
 * 
 * @param packet The packet to handle
 * @return int 0 if the packet is well handled, -1 otherwise
 */
int cast_ipv4(const u_char* packet);

#endif // IPv4_H