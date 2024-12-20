// Global libraries
#include <stdio.h>
#include <stdlib.h>

// Local header files
#include "ipv6.h"
#include "tcp.h"
#include "udp.h"
#include "icmpv6.h"

#define STR_IPv6_ADDR_LEN 5*8
static char *format_ipv6(const struct in6_addr ip) {      // Create an IPv6 string in the format XXXX::XXXX
    char *res = malloc(STR_IPv6_ADDR_LEN * sizeof(char));
    if (res == NULL)
        return NULL;
    
    if (inet_ntop(AF_INET6, &ip, res, STR_IPv6_ADDR_LEN) == NULL) {
        free(res);
        return NULL;
    }

    return res;
}

int ip6_handler (const u_char* packet, const struct ip6_hdr* ip6) {
    char *ipv6_src, *ipv6_dst;
    ipv6_src = format_ipv6(ip6->ip6_src);
    ipv6_dst = format_ipv6(ip6->ip6_dst);
    printf("IPv6: %s -> %s\n", ipv6_src, ipv6_dst);
    free(ipv6_src);
    free(ipv6_dst);

    switch (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
        case IPPROTO_TCP:
            cast_tcp(packet + sizeof(struct ip6_hdr), ip6->ip6_ctlun.ip6_un1.ip6_un1_plen - sizeof(struct ip6_hdr));
            break;
        case IPPROTO_UDP:
            cast_udp(packet + sizeof(struct ip6_hdr));
            break;
        case IPPROTO_ICMPV6:
            cast_icmp6(packet + sizeof(struct ip6_hdr));
            break;
        default:
            fprintf(stderr, "Unknown protocol on network layer. IP PROTOCOL: 0X%x\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
            return (-1);
    }
    return 0;
}

int cast_ipv6(const u_char* packet) {
    const struct ip6_hdr* ip;
    ip = (struct ip6_hdr*)(packet);
    ip6_handler(packet, ip);
    return 0;
}