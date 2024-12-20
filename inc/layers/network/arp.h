/**
 * @author Flavien Lallemant
 * @file arp.h
 * @brief ARP layer
 * @ingroup network
 * 
 * This file contains the definition of the ARP layer.
 * It provides the function to handle ARP packets.
 * 
 * @note There is a large debate on whether the ARP layer should be considered as a network layer or a data link layer. Some people even consider it as a layer 2.5. In this project, we consider it as a network layer.
 */

#ifndef ARP_H
#define ARP_H

#include "types.h"
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#define ARPPTYPE_IP ETHERTYPE_IP /**< ARP protocol type for IPv4 */
#define ARPPLEN_IP 4 /**< ARP protocol length for IPv4 */
#define ARPPTYPE_IP6 ETHERTYPE_IPV6 /**< ARP protocol type for IPv6 */
#define ARPPLEN_IPV6 16 /**< ARP protocol length for IPv6 */


/**
 * @brief Handle an ARP packet
 * 
 * This function handles an ARP packet.
 * 
 * @param packet The packet to handle
 * @return int 0 if the packet is well handled, -1 otherwise
 */
int cast_arp(const u_char *packet);

#endif // ARP_H