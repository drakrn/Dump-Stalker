/**
 * @author Flavien Lallemant
 * @file icmpv6.h
 * @brief ICMPv6 layer
 * @ingroup network
 * 
 * This file contains the definition of the ICMPv6 layer.
 * It provides the function to handle ICMPv6 packets.
 */

#ifndef ICMPv6_H
#define ICMPv6_H
#include <netinet/icmp6.h>
#include "types.h"

/**
 * @brief ICMPv6 type
 * @note This list completes the list of ICMPv6 types defined in <netinet/icmp6.h>
 */
#define ICMP6_NODE_INFORMATION_QUERY 139
#define ICMP6_NODE_INFORMATION_RESPONSE 140
#define ICMP6_INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION_MESSAGE 141
#define ICMP6_INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT_MESSAGE 142
#define ICMP6_MULTICAST_LISTENER_DISCOVERY_REPORTS 143
#define ICMP6_HOME_AGENT_ADDRESS_DISCOVERY_REQUEST 144
#define ICMP6_HOME_AGENT_ADDRESS_DISCOVERY_REPLY 145
#define ICMP6_MOBILE_PREFIX_SOLICITATION 146
#define ICMP6_MOBILE_PREFIX_ADVERTISEMENT 147
#define ICMP6_CERTIFICATION_PATH_SOLICITATION 148
#define ICMP6_CERTIFICATION_PATH_ADVERTISEMENT 149
#define ICMP6_MULTICAST_ROUTER_ADVERTISEMENT 151
#define ICMP6_MULTICAST_ROUTER_SOLICITATION 152
#define ICMP6_MULTICAST_ROUTER_TERMINATION 153
#define ICMP6_RPL_CONTROL_MESSAGE 155


/**
 * @brief Handle an ICMPv6 packet
 * 
 * This function handles an ICMPv6 packet.
 * 
 * @param packet The packet to handle
 * @return int 0 if the packet is well handled, -1 otherwise
 */
int cast_icmp6(const u_char *packet);

#endif // ICMPv6_H