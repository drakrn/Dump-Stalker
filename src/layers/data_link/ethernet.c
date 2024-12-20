/**
 * @author: Flavien Lallemant
 * @file: ethernet.c
 * @brief: Ethernet layer
 * @ingroup: data_link
 * 
 * This file contains the implementation of the Ethernet layer.
 * 
 * @see ethernet.h
 * @see cast_ethernet
 */

// Global libraries
#include <stdio.h>
#include <stdlib.h>

// Local header files
#include "ethernet.h"
#include "arp.h"
#include "ipv4.h"
#include "ipv6.h"


/**
 * @brief Format a MAC address
 * 
 * This function formats a MAC address in the format XX:XX:XX:XX:XX:XX.
 * 
 * @param ether_host The MAC address to format
 * @return char* The formatted MAC address
 * 
 * @note The returned string must be freed by the caller
 */
static char *format_mac(const u_char ether_host[ETH_ALEN])
{
    char *res = malloc(3 * ETH_ALEN * sizeof(char));
    if (res == NULL)
        return NULL;

    sprintf(res, "%02X:%02X:%02X:%02X:%02X:%02X", ether_host[0], ether_host[1],
            ether_host[2], ether_host[3], ether_host[4], ether_host[5]);

    return res;
}


/**
 * @brief Handle the ethertype
 * 
 * This function handles the ethertype of an Ethernet frame.
 * 
 * @param packet The packet to handle
 * @param ethernet The Ethernet frame
 * @return int 0 if the ethertype is well handled, 1 otherwise
 * 
 * @see cast_ipv4
 * @see cast_ipv6
 * @see cast_arp
 */
int ethertype_handler(const u_char *packet, const struct ether_header *ethernet)
{
    char *mac_shost = format_mac(ethernet->ether_shost);
    char *mac_dhost = format_mac(ethernet->ether_dhost);
    if (mac_shost == NULL || mac_dhost == NULL) {
        fprintf(stderr, "malloc\n");
        return 1;
    }

    printf("LINK: %s -> %s\n", mac_shost, mac_dhost);
    free(mac_shost);
    free(mac_dhost);
    
    switch (be16toh((ethernet->ether_type))) {
    case ETHERTYPE_IP:
        cast_ipv4(packet + sizeof(struct ether_header));
        break;
    case ETHERTYPE_IPV6:
        cast_ipv6(packet + sizeof(struct ether_header));
        break;
    case ETHERTYPE_ARP:
        cast_arp(packet + sizeof(struct ether_header));
        break;
    case ETHERTYPE_REVARP:
        fprintf(stderr, "No RARP handling yet.\n");
        break;
    default:
        fprintf(stderr, "Unknown protocol on link layer. ETHERTYPE: 0x%x\n",
                be16toh(ethernet->ether_type));
        return (-1);
    }
    return 0;
}


/**
 * @brief Handle an Ethernet frame
 * 
 * This function handles an Ethernet frame.
 * 
 * @param packet The packet to handle
 * @return int 0 if the packet is well handled, -1 otherwise
 * @see ethertype_handler
 */
int cast_ethernet(const u_char *packet)
{
    const struct ether_header *ethernet;
    ethernet = (struct ether_header *)packet;
    ethertype_handler(packet, ethernet);
    return 0;
}
