/**
 * @author Flavien Lallemant
 * @file icmp.c
 * @brief ICMP layer
 * @ingroup network
 * 
 * This file contains the implementation of the ICMP layer.
 * 
 * @see icmp.h
 * @see cast_icmp
 */

// Global libraries
#include <stdio.h>
#include <stdlib.h>

// Local header files
#include "icmp.h"


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
    "Precedence cutoff in effect"}; /**< Destination unreachable messages */
static const char *redirect_datagram_message[] = {
    "Redirect Datagram for the Network", "Redirect Datagram for the Host",
    "Redirect Datagram for the ToS & network",
    "Redirect Datagram for the ToS & host"}; /**< Redirect datagram messages */
static const char *time_exceeded_message[] = {
    "Time to live (TTL) expired in transit",
    "Fragment reassembly time exceeded"}; /**< Time exceeded messages */
static const char *bad_ip_header_message[] = {
    "Pointer indicates the error", "Missing a required option", "Bad length"}; /**< Bad IP header messages */
static const char *extended_echo_reply_message[] = {
    "No Error", "Malformed Query", "No Such Interface", "No Such Table Entry",
    "Multiple Interfaces Satisfy Query"}; /**< Extended echo reply messages */


/**
 * @brief Handle an ICMP message
 * 
 * This function handles an ICMP message.
 * 
 * @param hdr The ICMP header
 * @return int 0 if the message is well handled, -1 otherwise
 */
static int message_handler(const void *hdr)
{
    const struct icmphdr *icmp;
    icmp = (const struct icmphdr *)(hdr);
    switch (icmp->type) { // ICMP type
    case ICMP_ECHOREPLY: // ICMP Echo Reply
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP ECHO\n");
        break;
    case ICMP_DEST_UNREACH: // ICMP Destination Unreachable
        if (icmp->code > 15) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Destination Unreachable: %s\n",
               destination_unreachable_message[icmp->code]);
        break;
    case ICMP_SOURCE_QUENCH: // ICMP Source Quench
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Source Quench\n");
        break;
    case ICMP_REDIRECT: // ICMP Redirect
        if (icmp->code > 3) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Redirect Message: %s\n",
               redirect_datagram_message[icmp->code]);
        break;
    case ICMP_ECHO: // ICMP Echo Request
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Echo Request\n");
        break;
    case ICMP_ROUTER_ADVERT: // ICMP Router Advertisement
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Router Advertisement\n");
        break;
    case ICMP_ROUTER_SOLICIT: // ICMP Router Solicitation
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Router discovery/selection/solicitation\n");
        break;
    case ICMP_TIME_EXCEEDED: // ICMP Time Exceeded
        if (icmp->code > 1) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Time Exceeded: %s\n", time_exceeded_message[icmp->code]);
        break;
    case ICMP_PARAMETERPROB: // ICMP Parameter Problem
        if (icmp->code > 2) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Bad IP header: %s\n", bad_ip_header_message[icmp->code]);
        break;
    case ICMP_TIMESTAMP: // ICMP Timestamp Request
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Timestamp Request\n");
        break;
    case ICMP_TIMESTAMPREPLY: // ICMP Timestamp Reply
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Timestamp Response\n");
        break;
    case ICMP_INFO_REQUEST: // ICMP Information Request
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Information Request\n");
        break;
    case ICMP_INFO_REPLY: // ICMP Information Reply
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Information Reply\n");
        break;
    case ICMP_ADDRESS: // ICMP Address Mask Request
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Address mask request\n");
        break;
    case ICMP_ADDRESSREPLY: // ICMP Address Mask Reply
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Address mask reply\n");
        break;
    case ICMP_TRACEROUTE: // ICMP Traceroute
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Information Requestion (Traceroute)\n");
        break;
    case ICMP_EXT_ECHO: // ICMP Extended Echo Request
        if (icmp->code > 0) {
            fprintf(stderr, "Bad ICMP code\n");
            return (-1);
        }
        printf("ICMP Request Extended Echo\n");
        break;
    case ICMP_EXT_ECHOREPLY: // ICMP Extended Echo Reply
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


/**
 * @brief Handle an ICMP packet
 * 
 * This function handles an ICMP packet.
 * 
 * @param packet The packet to handle
 * @return int 0 if the packet is well handled
 * @see message_handler
 */
int cast_icmp(const u_char *packet)
{
    const struct icmphdr *icmp;
    icmp = (struct icmphdr *)(packet);
    message_handler(icmp);
    return 0;
}
