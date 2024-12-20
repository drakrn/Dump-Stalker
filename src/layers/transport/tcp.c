// Global libraries
#include <arpa/inet.h>
#include <stdio.h>

// Local header files
#include "tls.h"
#include "dns.h"
#include "ftp.h"
#include "http.h"
#include "pop.h"
#include "smtp.h"
#include "telnet.h"
#include "tcp.h"

void check_flags(const struct tcphdr *tcp)
{
    if (tcp->th_flags & TH_FIN)
        printf("FIN ");
    if (tcp->th_flags & TH_SYN)
        printf("SYN ");
    if (tcp->th_flags & TH_RST)
        printf("RST ");
    if (tcp->th_flags & TH_PUSH)
        printf("PSH ");
    if (tcp->th_flags & TH_ACK)
        printf("ACK ");
    if (tcp->th_flags & TH_URG)
        printf("URG ");
    printf("\n");
}

int tcp_handling(const u_char *packet, const struct tcphdr *tcp,
                 int remain_size)
{
    if (be16toh(tcp->th_sport) == 80 || be16toh(tcp->th_dport) == 80) {
        if (is_http(packet + tcp->doff * 4)) {
            printf("\t\tHTTP\n");
            printf("------------------------------------------------\n");
            printf("%.*s\n", remain_size, packet + tcp->doff * 4);
            printf("------------------------------------------------\n");
        }
    } else if (be16toh(tcp->th_sport) == 443 || be16toh(tcp->th_dport) == 443) {
        const struct tlshdr *tls;
        tls = (struct tlshdr *)(packet + tcp->th_off * 4);
        printf("\t\tHTTPS\n");
        printf("------------------------------------------------\n");
        printf("Encryption with ");
        switch (TLS_V(tls)) {
        case 0x00:
            printf("SSL 3.0\n");
            break;
        case 0x01:
            printf("TLS 1.0\n");
            break;
        case 0x02:
            printf("TLS 1.1\n");
            break;
        case 0x03:
            printf("TLS 1.2\n");
            break;
        case 0x04:
            printf("TLS 1.3\n");
            break;
        default:
            fprintf(stderr, "Unknown SSL/TLS version. VERSION: 0x%x\n",
                    TLS_V(tls));
        }
        // printf("%s\n", packet + tcp->th_off * 4 + sizeof(struct tlshdr));
        printf("------------------------------------------------\n");
    } else if (be16toh(tcp->th_sport) == 25 || be16toh(tcp->th_dport) == 25) {
        if (is_smtp(packet + tcp->doff * 4)) {
            printf("\t\tSMTP\n");
            printf("------------------------------------------------\n");
            printf("%.*s\n", remain_size, packet + tcp->doff * 4);
            printf("------------------------------------------------\n");
        }
    } else if (be16toh(tcp->th_sport) == 21 || be16toh(tcp->th_dport) == 21 ||
               be16toh(tcp->th_sport) == 20 || be16toh(tcp->th_dport) == 20) {
        if (is_ftp(packet + tcp->doff * 4)) {
            printf("\t\tFTP\n");
            printf("------------------------------------------------\n");
            printf("%.*s\n", remain_size, packet + tcp->doff * 4);
            printf("------------------------------------------------\n");
        }
    } else if (be16toh(tcp->th_sport) == 53 || be16toh(tcp->th_dport) == 53) {
        printf("\t\tDNS\n");
        printf("------------------------------------------------\n");
        cast_dns(packet + tcp->doff * 4, remain_size);
        printf("------------------------------------------------\n");
    } else if (be16toh(tcp->th_sport) == 110 || be16toh(tcp->th_dport) == 110) {
        if (is_pop(packet + tcp->doff * 4)) {
            printf("\t\tPOP3\n");
            printf("------------------------------------------------\n");
            printf("%.*s\n", remain_size, packet + tcp->doff * 4);
            printf("------------------------------------------------\n");
        }
    } else if (be16toh(tcp->th_sport) == 143 || be16toh(tcp->th_dport) == 143) {
        printf("\t\tIMAP\n");
        printf("------------------------------------------------\n");
        printf("%s\n", packet + tcp->doff * 4);
        printf("------------------------------------------------\n");
    } else if (be16toh(tcp->th_sport) == 993 || be16toh(tcp->th_dport) == 993) {
        const struct tlshdr *tls;
        tls = (struct tlshdr *)(packet + tcp->th_off * 4);
        printf("\t\tIMAP\n");
        printf("------------------------------------------------\n");
        printf("Encryption with ");
        switch (TLS_V(tls)) {
        case 0x00:
            printf("SSL 3.0\n");
            break;
        case 0x01:
            printf("TLS 1.0\n");
            break;
        case 0x02:
            printf("TLS 1.1\n");
            break;
        case 0x03:
            printf("TLS 1.2\n");
            break;
        case 0x04:
            printf("TLS 1.3\n");
            break;
        default:
            fprintf(stderr, "Unknown SSL/TLS version. VERSION: 0x%x\n",
                    TLS_V(tls));
        }
    } else if (be16toh(tcp->th_sport) == 23 || be16toh(tcp->th_dport) == 23) {
        printf("\t\ttelnet\n");
        printf("------------------------------------------------\n");
        telnet_handler(packet + tcp->doff * 4);
        printf("------------------------------------------------\n");
    }
    return 0;
}

int cast_tcp(const u_char *packet, int remain_size)
{
    const struct tcphdr *tcp;
    tcp = (struct tcphdr *)packet;
    printf("TCP.port: %d->%d\n", be16toh(tcp->th_sport),
           be16toh(tcp->th_dport));
    if (remain_size != tcp->doff * 4) {
        tcp_handling(packet, tcp, remain_size - tcp->doff * 4);
    } else {
        check_flags(tcp);
    }
    return 0;
}