/**
 * @author Flavien Lallemant
 * @file bootp.h
 * @brief BOOTP header definition
 * @ingroup application
 * 
 * This file contains the definition of the BOOTP header.
 * It provides functions to cast the BOOTP header from a packet.
 */

#ifndef BOOTP_H
#define BOOTP_H

#include "types.h"

/**
 * @brief BOOTP header structure
 * 
 * This structure represents the BOOTP header.
 */
struct bootphdr {
    uint8_t bh_op;
    uint8_t bh_htype;
    uint8_t bh_hlen;
    uint8_t bh_hops;
    uint32_t bh_xid;
    uint16_t bh_secs;
    struct {
        uint16_t unused;
    };
    uint32_t bh_ciaddr;
    uint32_t bh_yiaddr;
    uint32_t bh_siaddr;
    uint32_t bh_giaddr;
    uint8_t bh_chaddr[16];
    uint8_t bh_sname[64];
    uint8_t bh_file[128];
};

/**
 * @brief Cast BOOTP header
 * 
 * Get BOOTP header from packet.
 * 
 * @param packet Pointer to the packet
 * @return int 0 on success, -1 on error
 * 
 * @see cast_bootp
 */
int cast_bootp(const u_char* packet);

#endif // BOOTP_H