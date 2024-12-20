/**
 * @author Flavien Lallemant
 * @file udp.c
 * @brief UDP layer
 * @ingroup transport
 * 
 * This file contains the implementation of the UDP layer.
 * 
 * @see udp.h
 * @see cast_udp
 */

// Global libraries
#include <stdio.h>

// Local header files
#include "udp.h"
#include "bootp.h"
#include "dns.h"

/**
 * @brief Handle a UDP packet
 * 
 * This function handles a UDP packet.
 * 
 * @param packet The packet to handle
 * @param udp The UDP header
 * @param data_size The size of the data
 * @return int 0 if the packet is well handled
 * 
 * @see cast_bootp
 * @see cast_dns
 */
int udp_handling(const u_char *packet, const struct udphdr *udp, int data_size)
{
    if (be16toh(udp->uh_sport) == 67 || be16toh(udp->uh_dport) == 67 ||
        be16toh(udp->uh_dport) == 68 || be16toh(udp->uh_dport) == 68) {
        printf("------------------------------------------------\n");
        cast_bootp(packet + 8);
        printf("------------------------------------------------\n");
    } else if (be16toh(udp->uh_sport) == 53 || be16toh(udp->uh_dport) == 53) {
        printf("------------------------------------------------\n");
        cast_dns(packet + 8, data_size);
        printf("------------------------------------------------\n");
    }
    return 0;
}


/**
 * @brief Handle a UDP packet
 * 
 * This function handles a UDP packet.
 * 
 * @param packet The packet to handle
 * @return int 0 if the packet is well handled
 */
int cast_udp(const u_char *packet)
{
    const struct udphdr *udp;
    udp = (struct udphdr *)packet;
    printf("UDP.port: %d->%d\n", be16toh(udp->uh_sport), be16toh(udp->uh_dport));
    if (be16toh(udp->uh_ulen) > 8) {
        udp_handling(packet, udp, be16toh(udp->uh_ulen) - 8);
    }
    return 0;
}