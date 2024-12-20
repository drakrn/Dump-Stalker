// Global libraries
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Local librairies
#include "arp.h"

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

static char *format_mac(const u_char ether_host[ETH_ALEN])
{ // Create a MAC string in the format XX:XX:XX:XX:XX:XX
    char *res = malloc(3 * ETH_ALEN * sizeof(char));
    if (res == NULL)
        return NULL;

    sprintf(res, "%02X:%02X:%02X:%02X:%02X:%02X", ether_host[0], ether_host[1],
            ether_host[2], ether_host[3], ether_host[4], ether_host[5]);

    return res;
}

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

char *getsenderaddr(const u_char *packet, const struct arphdr *arp, int type)
{
    return getaddr(packet, arp, 1, type);
}

char *gettargetaddr(const u_char *packet, const struct arphdr *arp, int type)
{
    return getaddr(packet, arp, 2, type);
}

int arp_handler(const u_char *packet, const struct arphdr *arp)
{
    switch (be16toh(arp->ar_op)) {
    case ARPOP_REQUEST: {
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
    case ARPOP_REPLY: {
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

int cast_arp(const u_char *packet)
{
    const struct arphdr *arp;
    arp = (struct arphdr *)packet;
    arp_handler(packet, arp);
    return 0;
}