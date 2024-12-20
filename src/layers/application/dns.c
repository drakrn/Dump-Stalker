/**
 * @author Flavien Lallemant
 * @file dns.c
 * @brief DNS header functions
 * @ingroup application
 * 
 * This file contains the functions to cast the DNS header from a packet.
 * 
 * @see dns.h
 * @see cast_dns
 */

// Global libraries
#include <stdlib.h>
#include <string.h>

// Local header files
#include "dns.h"


/**
 * @brief Check question segment of DNS header
 * 
 * @param packet Pointer to the packet
 * @param questions Number of questions
 * @return int Offset at the end of the question segment
 */
int check_question(const u_char *packet, int questions)
{
    printf("\t- %dx QUERIE(S):\n", questions);
    int off = 0;
    for (int i = 0; i < questions; i++) { // Loop over questions
        char name[256];
        int j = 0;
        // Parse name field of the question
        while (1) {
            if (packet[j] == 0) {
                break;
            }
            if (packet[j] >= 32 && packet[j] <= 126) {
                name[j] = packet[j];
            } else {
                name[j] = '.';
            }
            j++;
        }
        name[j] = '\0';
        printf("\t\t- NAME: %s\n", name);
        off = j + 1; // Skip the null byte

        // Parse type field of the question
        uint16_t type = be16toh(*(uint16_t *)(packet + off));
        switch (type) {
        case 1:
            printf("\t\t- TYPE: A\n");
            break;
        case 2:
            printf("\t\t- TYPE: NS\n");
            break;
        case 5:
            printf("\t\t- TYPE: CNAME\n");
            break;
        case 6:
            printf("\t\t- TYPE: SOA\n");
            break;
        case 12:
            printf("\t\t- TYPE: PTR\n");
            break;
        case 15:
            printf("\t\t- TYPE: MX\n");
            break;
        case 16:
            printf("\t\t- TYPE: TXT\n");
            break;
        case 28:
            printf("\t\t- TYPE: AAAA\n");
            break;
        case 33:
            printf("\t\t- TYPE: SRV\n");
            break;
        }
        off += 2; // Skip the 2 bytes of the type field

        // Parse class field of the question
        uint16_t class = be16toh(*(uint16_t *)(packet + off));
        switch (class) {
        case 0:
            printf("\t\t- CLASS: RESERVED\n");
            break;
        case 1:
            printf("\t\t- CLASS: IN\n");
            break;
        case 3:
            printf("\t\t- CLASS: CH\n");
            break;
        case 4:
            printf("\t\t- CLASS: HS\n");
            break;
        case 254:
            printf("\t\t- CLASS: QCLASS NONE\n");
            break;
        case 255:
            printf("\t\t- CLASS: QCLASS *\n");
            break;
        }
        off += 2; // Skip the 2 bytes of the class field
    }
    return off;
}


/**
 * @brief Check answer segment of DNS header
 * 
 * @param packet Pointer to the packet
 * @param answers Number of answers
 * @return int Offset at the end of the answer segment
 */
int check_answer(const u_char *packet, int answers)
{
    printf("\t- %dx ANSWER(S):\n", answers);
    int off = 0;
    for (int i = 0; i < answers; i++) { // Loop over answers
        char name[256];
        int j = 0;
        // Parse name field of the answer
        while (1) {
            if (packet[j] == 0) {
                break;
            }
            if (packet[j] >= 32 && packet[j] <= 126) {
                name[j] = packet[j];
            } else {
                name[j] = '.';
            }
            j++;
        }
        name[j] = '\0';
        printf("\t\t- NAME: %s\n", name);
        off = j + 1; // Skip the null byte

        // Parse type field of the answer
        uint16_t type = be16toh(*(uint16_t *)(packet + off));
        switch (type) {
        case 1:
            printf("\t\t- TYPE: A\n");
            break;
        case 2:
            printf("\t\t- TYPE: NS\n");
            break;
        case 5:
            printf("\t\t- TYPE: CNAME\n");
            break;
        case 6:
            printf("\t\t- TYPE: SOA\n");
            break;
        case 12:
            printf("\t\t- TYPE: PTR\n");
            break;
        case 15:
            printf("\t\t- TYPE: MX\n");
            break;
        case 16:
            printf("\t\t- TYPE: TXT\n");
            break;
        case 28:
            printf("\t\t- TYPE: AAAA\n");
            break;
        case 33:
            printf("\t\t- TYPE: SRV\n");
            break;
        }
        off += 2; // Skip the 2 bytes of the type field

        // Parse class field of the answer
        uint16_t class = be16toh(*(uint16_t *)(packet + off));
        switch (class) {
        case 0:
            printf("\t\t- CLASS: RESERVED\n");
            break;
        case 1:
            printf("\t\t- CLASS: IN\n");
            break;
        case 3:
            printf("\t\t- CLASS: CH\n");
            break;
        case 4:
            printf("\t\t- CLASS: HS\n");
            break;
        case 254:
            printf("\t\t- CLASS: QCLASS NONE\n");
            break;
        case 255:
            printf("\t\t- CLASS: QCLASS *\n");
            break;
        }
        off += 2; // Skip the 2 bytes of the class field

        // Parse TTL field of the answer
        uint32_t ttl = be32toh(*(uint32_t *)(packet + off));
        printf("\t\t- TTL: %d\n", ttl);
        off += 4; // Skip the 4 bytes of the TTL field

        // Parse RDLENGTH field of the answer
        int rdlength = be16toh(*(uint16_t *)(packet + off));
        printf("\t\t- RDATA LENGTH: %d\n", rdlength);
        off += 2; // Skip the 2 bytes of the RDLENGTH field

        switch (type) {
        case 1: // A
            printf("\t\t- ADDRESS: %u.%u.%u.%u\n", packet[off], packet[off + 1],
                   packet[off + 2], packet[off + 3]);
            off += 4;
            break;
        case 28: // AAAA
            printf("\t\t- ADDRESS: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
                   packet[off], packet[off + 1], packet[off + 2],
                   packet[off + 3], packet[off + 4], packet[off + 5],
                   packet[off + 6], packet[off + 7]);
            off += 16;
            break;
        }
    }
    return off;
}


/**
 * @brief Cast DNS header
 * 
 * Get DNS header from packet.
 * 
 * @param packet Pointer to the packet
 * @param data_size Size of the data
 * @return int 0 on success
 */
int cast_dns(const u_char *packet, int data_size)
{
    if (data_size) { // To pass unused parameter warning
        ;
    }
    const struct dnshdr *dns;
    dns = (struct dnshdr *)packet;
    printf("\t- TRANSACTION ID: 0x%04x\n", be16toh(dns->dh_xid));

    uint16_t flags = be16toh(dns->dh_flags);
    printf("\t- FLAGS: 0x%04x\n", flags);

    switch ((flags & DH_QR) >> 15) {
    case 0:
        printf("\t- QR: (0) QUERY\n");
        break;
    case 1:
        printf("\t- QR: (1) REPLY\n");
        break;
    }
    switch ((flags & DH_OP) >> 11) {
    case 0:
        printf("\t- OP: (0) QUERY\n");
        break;
    case 1:
        printf("\t- OP: (1) IQUERY\n");
        break;
    case 2:
        printf("\t- OP: (2) STATUS\n");
        break;
    }
    if (flags & DH_AA)
        printf("\t- AA: (1) AUTHORITATIVE ANSWER\n");
    if (flags & DH_TC)
        printf("\t- TC: (1) TRUNCATED\n");
    if (flags & DH_RD)
        printf("\t- RD: (1) RECURSION DESIRED\n");
    if (flags & DH_RA)
        printf("\t- RA: (1) RECURSION AVAILABLE\n");
    
    switch (flags & DH_RCODE) {
    case 0:
        printf("\t- RCODE: (0) NO ERROR\n");
        break;
    case 1:
        printf("\t- RCODE: (1) FORMAT ERROR\n");
        break;
    case 2:
        printf("\t- RCODE: (2) SERVER FAILURE\n");
        break;
    case 3:
        printf("\t- RCODE: (3) NAME ERROR\n");
        break;
    case 4:
        printf("\t- RCODE: (4) NOT IMPLEMENTED\n");
        break;
    case 5:
        printf("\t- RCODE: (5) REFUSED\n");
        break;
    case 6:
        printf("\t- RCODE: (6) YXDOMAIN\n");
        break;
    case 7:
        printf("\t- RCODE: (7) YXRRSET\n");
        break;
    case 8:
        printf("\t- RCODE: (8) NOTAUTH\n");
        break;
    case 9:
        printf("\t- RCODE: (9) NOTZONE\n");
        break;
    }

    int off = 12; // Start after the static part of the header
    if (dns->dh_questions > 0) {
        off += check_question(packet + off, be16toh(dns->dh_questions));
    }
    if (dns->dh_answers > 0) {
        off += check_answer(packet + off, be16toh(dns->dh_answers));
    }
    if (dns->dh_autorityRRs > 0) {
        printf("\t- %dx AUTHORITY RRs:\n", dns->dh_autorityRRs);
        printf("\t\t- NOT IMPLEMENTED YET\n");
    }
    if (dns->dh_additionalRRs > 0) {
        printf("\t- %dx ADDITIONAL RRs:\n", dns->dh_additionalRRs);
        printf("\t\t- NOT IMPLEMENTED YET\n");
    }
    return 0;
}