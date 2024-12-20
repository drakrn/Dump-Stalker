// Global libraries
#include <stdio.h>
#include <stdlib.h>

// Local header files
#include "icmp.h"

/* ICMP messages */
static const char *destination_unreachable_message[] = {
    "Destination network unreachable",
    "Destination host unreachable ",
    "Destination protocol unreachable ",
    "Destination port unreachable",
    "Fragmentation required, and DF flag set",
    "Source route failed",
    "Destination network unknown",
    "Destination host unknown",
    "Source host isolated",
    "Network administratively prohibited",
    "Host administratively prohibited",
    "Network unreachable for ToS",
    "Host unreachable for ToS",
    "Communication administratively prohibited",
    "Host Precedence Violation",
    "Precedence cutoff in effect"};
static const char *redirect_datagram_message[] = {
    "Redirect Datagram for the Network", "Redirect Datagram for the Host",
    "Redirect Datagram for the ToS & network",
    "Redirect Datagram for the ToS & host"};
static const char *time_exceeded_message[] = {
    "Time to live (TTL) expired in transit",
    "Fragment reassembly time exceeded"};
static const char *bad_ip_header_message[] = {
    "Pointer indicates the error", "Missing a required option", "Bad length"};
static const char *extended_echo_reply_message[] = {
    "No Error", "Malformed Query", "No Such Interface", "No Such Table Entry",
    "Multiple Interfaces Satisfy Query"};

static int message_handler(const void *hdr)
{
    const struct icmphdr *icmp;
    icmp = (const struct icmphdr *)(hdr);
    switch (icmp->type) {
    case ICMP_ECHOREPLY:
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP ECHO\n");
        break;
    case ICMP_DEST_UNREACH:
        if (icmp->code > 15) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Destination Unreachable: %s\n",
               destination_unreachable_message[icmp->code]);
        break;
    case ICMP_SOURCE_QUENCH:
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Source Quench\n");
        break;
    case ICMP_REDIRECT:
        if (icmp->code > 3) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Redirect Message: %s\n",
               redirect_datagram_message[icmp->code]);
        break;
    case ICMP_ECHO:
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Echo Request\n");
        break;
    case ICMP_ROUTER_ADVERT:
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Router Advertisement\n");
        break;
    case ICMP_ROUTER_SOLICIT:
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Router discovery/selection/solicitation\n");
        break;
    case ICMP_TIME_EXCEEDED:
        if (icmp->code > 1) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Time Exceeded: %s\n", time_exceeded_message[icmp->code]);
        break;
    case ICMP_PARAMETERPROB:
        if (icmp->code > 2) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Bad IP header: %s\n", bad_ip_header_message[icmp->code]);
        break;
    case ICMP_TIMESTAMP:
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Timestamp Request\n");
        break;
    case ICMP_TIMESTAMPREPLY:
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Timestamp Response\n");
        break;
    case ICMP_INFO_REQUEST:
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Information Request\n");
        break;
    case ICMP_INFO_REPLY:
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Information Reply\n");
        break;
    case ICMP_ADDRESS:
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Address mask request\n");
        break;
    case ICMP_ADDRESSREPLY:
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Address mask reply\n");
        break;
    case ICMP_TRACEROUTE:
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Information Requestion (Traceroute)\n");
        break;
    case ICMP_EXT_ECHO:
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Request Extended Echo\n");
        break;
    case ICMP_EXT_ECHOREPLY:
        if (icmp->code > 4) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Reply Extended Echo: %s\n",
               extended_echo_reply_message[icmp->code]);
        break;
    default:
        fprintf(stderr, "Unknown ICMP type. ICMP TYPE: %x\n", icmp->type);
        break;
    }

    return 0;
}

int cast_icmp(const u_char *packet)
{
    const struct icmphdr *icmp;
    icmp = (struct icmphdr *)(packet);
    message_handler(icmp);
    return 0;
}
