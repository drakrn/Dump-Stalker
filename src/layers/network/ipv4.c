/**
 * @author Flavien Lallemant
 * @file ipv4.c
 * @brief IPv4 layer
 * @ingroup network
 * 
 * This file contains the implementation of the IPv4 layer.
 * 
 * @see ipv4.h
 * @see cast_ipv4
 */

// Global libraries
#include <stdio.h>
#include <stdlib.h>

// Local header files
#include "icmp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "tcp.h"
#include "udp.h"


/**
 * @brief Format an IPv4 address
 * 
 * This function formats an IPv4 address in the format A.B.C.D.
 * 
 * @param ip_addr The IPv4 address to format
 * @return char* The formatted IPv4 address
 * 
 * @note The returned string must be freed by the caller
 */
#define STR_IPv4_ADDR_LEN 16
static char *format_ipv4(uint32_t ip_addr)
{
    char *res = malloc(STR_IPv4_ADDR_LEN * sizeof(char));
    if (res == NULL) {
        return NULL;
    }
    sprintf(res, "%u.%u.%u.%u", (ip_addr >> 24) & 0xFF, (ip_addr >> 16) & 0xFF,
            (ip_addr >> 8) & 0xFF, (ip_addr) & 0xFF);

    return res;
}

/**
 * @brief Handle an IPv4 packet
 * 
 * This function handles an IPv4 packet.
 * 
 * @param packet The packet to handle
 * @param ip The IPv4 header
 * @return int 0 if the packet is well handled
 * @see cast_tcp
 * @see cast_udp
 * @see cast_icmp
 * @see cast_ipv6
 */
int ip_handler(const u_char *packet, const struct iphdr *ip)
{
    /* Print IPv4 source and destination */
    char *ipv4_src, *ipv4_dst;
    ipv4_src = format_ipv4(ntohl(ip->saddr));
    ipv4_dst = format_ipv4(ntohl(ip->daddr));
    printf("IP: %s -> %s\n", ipv4_src, ipv4_dst);
    free(ipv4_src);
    free(ipv4_dst);

    switch (ip->protocol) {
    case IPPROTO_TCP:
        cast_tcp(packet + ip->ihl * 4, be16toh(ip->tot_len) - ip->ihl * 4);
        break;
    case IPPROTO_UDP:
        cast_udp(packet + ip->ihl * 4);
        break;
    case IPPROTO_ICMP:
        cast_icmp(packet + ip->ihl * 4);
        break;
    case IPPROTO_IPV6:
        cast_ipv6(packet + ip->ihl * 4);
        break;
    default:
        fprintf(stderr,
                "Unknown protocol on network layer. IP PROTOCOL: 0X%x\n",
                ip->protocol);
        return (-1);
    }
    return 0;
}


/**
 * @brief Handle an IPv4 packet
 * 
 * This function handles an IPv4 packet.
 * 
 * @param packet The packet to handle
 * @return int 0 if the packet is well handled
 * @see ip_handler
 */
int cast_ipv4(const u_char *packet)
{
    const struct iphdr *ip;
    ip = (struct iphdr *)(packet);
    ip_handler(packet, ip);
    return 0;
}