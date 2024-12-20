// Global libraries
#include <stdio.h>

// Local header files
#include "udp.h"
#include "bootp.h"
#include "dns.h"

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