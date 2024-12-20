/**
 * @author Flavien Lallemant
 * @file bootp.c
 * @brief BOOTP header functions
 * @ingroup application
 * 
 * This file contains the functions to cast the BOOTP header from a packet.
 * 
 * @see bootp.h
 * @see cast_bootp
 */

// Global libraries
#include <stdlib.h>
#include <string.h>

// Local header files
#include "bootp.h"

#define DHCP_MCOOKIE 0x63825363 /**< DHCP magic cookie */
#define VENDOR_OFF 236 /**< Vendor specific information offset */


/**
 * @brief Format hardware address
 * 
 * Format hardware address from BOOTP header.
 * 
 * @param bootp BOOTP header
 * @return char* Formatted hardware address
 */
char *format_haddr(const struct bootphdr *bootp)
{
    switch (bootp->bh_htype) {
    case 1: {
        char *res = malloc(3 * 6 * sizeof(char));
        if (res == NULL)
            return NULL;
        sprintf(res, "%02X:%02X:%02X:%02X:%02X:%02X", bootp->bh_chaddr[0],
                bootp->bh_chaddr[1], bootp->bh_chaddr[2], bootp->bh_chaddr[3],
                bootp->bh_chaddr[4], bootp->bh_chaddr[5]);
        return res;
    }
    default:
        fprintf(stderr, "Unsupported hardware type 0x%x\n", bootp->bh_htype);
        return NULL;
    }
}

/**
 * @brief Analyze DHCP TLV
 * 
 * Analyze DHCP TLV.
 * 
 * @param T Type
 * @param L Length
 * @param V Value
 */
void dhcp_tlv_analyze(uint8_t T, uint8_t L, uint8_t *V)
{
    switch (T) {
    case 1:
        printf("\t- SUBNET MASK: %u.%u.%u.%u\n", V[0], V[1], V[2], V[3]);
        break;
    case 2:
        printf("\t- TIME OFFSET: %s\n", V);
        break;
    case 3:
        printf("\t- ROUTER: %u.%u.%u.%u\n", V[0], V[1], V[2], V[3]);
        break;
    case 6:
        printf("\t- DNS: %u.%u.%u.%u\n", V[0], V[1], V[2], V[3]);
        break;
    case 12:
        printf("\t- HOST NAME: %s\n", V);
        break;
    case 15:
        printf("\t- DOMAIN NAME: %s\n", V);
        break;
    case 28:
        printf("\t- BROADCAST ADDRESS: %s\n", V);
        break;
    case 44:
        printf("\t- NETBIOS OVER TCP/IP NAME SERVER: %s\n", V);
        break;
    case 47:
        printf("\t- NETBIOS OVER TCP/IP SCOPE: %s\n", V);
        break;
    case 50:
        printf("\t- REQUESTED IP ADDRESS: %u.%u.%u.%u\n", V[0], V[1], V[2], V[3]);
        break;
    case 51:
        printf("\t- LEASE TIME: %d\n", be32toh(*(uint32_t *)V));
        break;
    case 53: {
        printf("\t- MESSAGE TYPE: ");
        switch (V[0]) {
        case 1:
            printf("DISCOVER\n");
            break;
        case 2:
            printf("OFFER\n");
            break;
        case 3:
            printf("REQUEST\n");
            break;
        case 5:
            printf("ACK\n");
            break;
        case 7:
            printf("RELEASE\n");
            break;
        default:
            printf("UNKNOWN\n");
        }
        break;
    }
    case 54:
        printf("\t- SERVER IDENTIFIER: %u.%u.%u.%u\n", V[0], V[1], V[2], V[3]);
        break;
    case 55: {
        printf("\t- PARAMETER REQUEST LIST: \n");
        for (int i = 0; i < L; i++) {
            switch(V[i]) {
                case 1:
                    printf("\t\t(1)\tSUBNET MASK\n");
                    break;
                case 2:
                    printf("\t\t(2)\tTIME OFFSET\n");
                    break;
                case 3:
                    printf("\t\t(3)\tROUTER\n");
                    break;
                case 6:
                    printf("\t\t(6)\tDNS\n");
                    break;
                case 12:
                    printf("\t\t(12)\tHOST NAME\n");
                    break;
                case 15:
                    printf("\t\t(15)\tDOMAIN NAME\n");
                    break;
                case 42:
                    printf("\t\t(42)\tNETWORK TIME PROTOCOL SERVERS\n");
                    break;
                case 44:
                    printf("\t\t(44)\tNETBIOS OVER TCP/IP NAME SERVER\n");
                    break;
                case 47:
                    printf("\t\t(47)\tNETBIOS OVER TCP/IP SCOPE\n");
                    break;
                case 51:
                    printf("\t\t(51)\tLEASE TIME\n");
                    break;
                case 54:
                    printf("\t\t(54)\tSERVER IDENTIFIER\n");
                    break;
                default:
                    printf("\t\tPARAMETER NOT IMPLEMENTED YET %d\n", V[i]);
            }
        }
        break;
    }
    case 58: 
        printf("\t- REBINDING TIME VALUE: %d\n", be32toh(*(uint32_t*)V));
        break;
    case 61: {
        printf("\t- CLIENT IDENTIFIER: ");
        uint8_t htype = (uint8_t)V[0];
        if (htype == 1) {
            printf("%02X:%02X:%02X:%02X:%02X:%02X\n", V[1], V[2], V[3], V[4],
                   V[5], V[6]);
        } else {
            printf("UNKNOWN HTYPE\n");
        }
        break;
    }
    }
}

/**
 * @brief Walk vendor specific information
 * 
 * Walk vendor specific information.
 * 
 * @param packet Pointer to the packet
 * @param magic_cookie Magic cookie
 */
void walk_vendor(const u_char *packet, uint32_t magic_cookie)
{
    printf("OPTIONS:\n");
    int off = 0;
    while (1) {
        uint8_t T;
        T = *(uint8_t *)(packet + off);
        if (T == 0x00) { // End of options
            break;
        }
        off++;
        uint8_t L;
        L = *(uint8_t *)(packet + off);
        off++;
        uint8_t *V = malloc(L * sizeof(uint8_t));
        if (V == NULL) {
            continue;
        }
        memcpy(V, packet + off, L);

        off += L;
        switch (magic_cookie) {
        case DHCP_MCOOKIE:
            dhcp_tlv_analyze(T, L, V);
            break;
        }
        free(V);
    }
}


/**
 * @brief Cast BOOTP header
 * 
 * Get BOOTP header from packet.
 * 
 * @param packet Pointer to the packet
 * @return int 0 on success, -1 on error
 * 
 * @see bootp.h
 */
int cast_bootp(const u_char *packet)
{
    const struct bootphdr *bootp;
    bootp = (struct bootphdr *)packet;
    if (bootp->bh_op == 1 || bootp->bh_op == 2) {
        switch (be32toh(*(uint32_t *)(packet + VENDOR_OFF))) {
        case DHCP_MCOOKIE:
            printf("BOOTP/DHCP ");
            break;
        default:
            printf("BOOTP ");
        }
        switch (bootp->bh_op) {
        case 1: {
            char *chaddr = format_haddr(bootp);
            printf("REQUEST from %s\n", chaddr ? chaddr : "");
            free(chaddr);
            break;
        }
        case 2:
            printf("REPLY\n");
            break;
        }

        walk_vendor(packet + VENDOR_OFF + 4,
                    be32toh(*(uint32_t *)(packet + VENDOR_OFF)));
    }
    return 0;
}