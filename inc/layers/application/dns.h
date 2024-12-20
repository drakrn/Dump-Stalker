/**
 * @author Flavien Lallemant
 * @file dns.h
 * @brief DNS Protocol Header File
 * @ingroup application
 * 
 * This file contains the definition of the DNS header.
 * It provides functions to cast the DNS header from a packet.
 */

#ifndef DNS_H
#define DNS_H

#include "types.h"

/**
 * @brief DNS header structure
 * 
 * This structure represents the DNS header.
 */
struct dnshdr {
    uint16_t dh_xid;
    uint16_t dh_flags;
#define DH_QR 0x8000
#define DH_OP 0x7800
#define DH_AA 0x0400
#define DH_TC 0x0200
#define DH_RD 0x0100
#define DH_RA 0x0080
#define DH_Z 0x0070
#define DH_RCODE 0x000F
    uint16_t dh_questions;
    uint16_t dh_answers;
    uint16_t dh_autorityRRs;
    uint16_t dh_additionalRRs;
};

/**
 * @brief Cast DNS header
 * 
 * Get DNS header from packet.
 * 
 * @param packet Pointer to the packet
 * @param data_size Size of the data
 * @return int 0 on success, -1 on error
 * 
 * @see cast_dns
 */
int cast_dns(const u_char* packet, int data_size);

#endif // DNS_H