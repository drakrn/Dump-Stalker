/**
 * @author Flavien Lallemant
 * @file arp.c
 * @brief ARP layer
 * @ingroup network
 * 
 * This file contains the implementation of the ARP layer.
 * 
 * @see arp.h
 * @see cast_arp
 */

// Global libraries
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Local librairies
#include "arp.h"


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
{ // Create an IPv4 string in the format A.B.C.D
    char *res = malloc(STR_IPv4_ADDR_LEN * sizeof(char));
    if (res == NULL) {
        return NULL;
    }
    sprintf(res, "%u.%u.%u.%u", (ip_addr >> 24) & 0xFF, (ip_addr >> 16) & 0xFF,
            (ip_addr >> 8) & 0xFF, (ip_addr) & 0xFF);

    return res;
}

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
{ // Create a MAC string in the format XX:XX:XX:XX:XX:XX
    char *res = malloc(3 * ETH_ALEN * sizeof(char));
    if (res == NULL)
        return NULL;

    sprintf(res, "%02X:%02X:%02X:%02X:%02X:%02X", ether_host[0], ether_host[1],
            ether_host[2], ether_host[3], ether_host[4], ether_host[5]);

    return res;
}


/**
 * @brief Get an address from an ARP packet
 * 
 * This function extracts an address from an ARP packet.
 * 
 * @param packet The packet to extract the address from
 * @param arp The ARP header
 * @param who The address to extract (1 for sender, 2 for target)
 * @param type The type of address to extract (1 for MAC, 2 for IP)
 * @return char* The extracted address
 * 
 * @note The returned string must be freed by the caller
 */
char *getaddr(const u_char *packet, const struct arphdr *arp, int who, int type)
{
    if (be16toh(arp->ar_pro) == ARPPTYPE_IP && arp->ar_pln == ARPPLEN_IP) {
        int offset = sizeof(struct arphdr);
        if (who == 1 && type == 1) {
            return format_mac((u_char *)(packet + offset));
        }
        offset += arp->ar_hln;
        if (who == 1 && type == 2) {
            return format_ipv4(be32toh(*(uint32_t *)(packet + offset)));
        }
        offset += arp->ar_pln;
        if (who == 2 && type == 1) {
            return format_mac((u_char *)(packet + offset));
        }
        offset += arp->ar_hln;
        if (who == 2 && type == 2) {
            return format_ipv4(be32toh(*(uint32_t *)(packet + offset)));
        }
    }
    return NULL;
}

/**
 * @brief Get the sender address from an ARP packet (MAC or IP)
 * 
 * This function extracts the sender MAC address from an ARP packet.
 * 
 * @param packet The packet to extract the address from
 * @param arp The ARP header
 * @param type The type of address to extract (1 for MAC, 2 for IP)
 * @return char* The extracted address
 * 
 * @note The returned string must be freed by the caller
 */
char *getsenderaddr(const u_char *packet, const struct arphdr *arp, int type)
{
    return getaddr(packet, arp, 1, type);
}


/**
 * @brief Get the target address from an ARP packet (MAC or IP)
 * 
 * This function extracts the target MAC address from an ARP packet.
 * 
 * @param packet The packet to extract the address from
 * @param arp The ARP header
 * @param type The type of address to extract (1 for MAC, 2 for IP)
 * @return char* The extracted address
 * 
 * @note The returned string must be freed by the caller
 */
char *gettargetaddr(const u_char *packet, const struct arphdr *arp, int type)
{
    return getaddr(packet, arp, 2, type);
}


/**
 * @brief Handle an ARP packet
 * 
 * This function handles an ARP packet.
 * 
 * @param packet The packet to handle
 * @param arp The ARP header
 * @return int 0 if the packet is well handled, 1 otherwise
 */
int arp_handler(const u_char *packet, const struct arphdr *arp)
{
    switch (be16toh(arp->ar_op)) { // ARP operation code
    case ARPOP_REQUEST: { // ARP Request
        char *TPA, *THA, *SPA, *SHA;
        TPA = gettargetaddr(packet, arp, 2);
        THA = gettargetaddr(packet, arp, 1);
        SPA = getsenderaddr(packet, arp, 2);
        SHA = getsenderaddr(packet, arp, 1);
        if (TPA == NULL || SPA == NULL || THA == NULL) {
            fprintf(stderr, "null addr\n");
            return 1;
        }
        if ((strcmp(TPA, SPA) == 0) &&
            (strcmp(THA, "00:00:00:00:00:00") == 0)) {
            printf("ARP Announcement: %s is at %s\n", SPA, SHA);
        } else if (SHA && TPA && (strcmp(SPA, "0.0.0.0") == 0) && (strcmp(THA, "00:00:00:00:00:00") == 0)) {
            printf("ARP Probing %s\n", TPA);
        } else {
            printf("ARP Request: Who has %s? Tell %s\n", TPA, SPA);
        }
        free(THA);
        free(TPA);
        free(SPA);
        free(SHA);
        break;
    }
    case ARPOP_REPLY: { // ARP Reply
        char *TPA, *THA, *SPA, *SHA;
        TPA = gettargetaddr(packet, arp, 2);
        THA = gettargetaddr(packet, arp, 1);
        SPA = getsenderaddr(packet, arp, 2);
        SHA = getsenderaddr(packet, arp, 1);
        if (TPA == NULL || SPA == NULL || THA == NULL) {
            fprintf(stderr, "null addr\n");
            return 1;
        }
        if ((strcmp(TPA, SPA) == 0) &&
            (strcmp(THA, "00:00:00:00:00:00") == 0)) {
            printf("ARP Announcement for %s\n", SPA);
        } else {
            printf("ARP Reply: %s is at %s\n", SPA, SHA);
        }
        free(THA);
        free(TPA);
        free(SPA);
        free(SHA);
        break;
    }
    default:
        fprintf(stderr, "Unsupported ARP operation code 0x%02x\n",
                be16toh(arp->ar_op));
    }
    return 0;
}


/**
 * @brief Handle an ARP packet
 * 
 * This function handles an ARP packet.
 * 
 * @param packet The packet to handle
 * @return int 0 if the packet is well handled
 * @see arp_handler
 */
int cast_arp(const u_char *packet)
{
    const struct arphdr *arp;
    arp = (struct arphdr *)packet;
    arp_handler(packet, arp);
    return 0;
}