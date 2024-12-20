// Global libraries
#include <stdio.h>
#include <stdlib.h>

// Local header files
#include "ethernet.h"
#include "arp.h"
#include "ipv4.h"
#include "ipv6.h"

static char *format_mac(const u_char ether_host[ETH_ALEN])
{ // Create a MAC string in the format XX:XX:XX:XX:XX:XX
    char *res = malloc(3 * ETH_ALEN * sizeof(char));
    if (res == NULL)
        return NULL;

    sprintf(res, "%02X:%02X:%02X:%02X:%02X:%02X", ether_host[0], ether_host[1],
            ether_host[2], ether_host[3], ether_host[4], ether_host[5]);

    return res;
}

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

int cast_ethernet(const u_char *packet)
{
    const struct ether_header *ethernet;
    ethernet = (struct ether_header *)packet;
    ethertype_handler(packet, ethernet);
    return 0;
}
