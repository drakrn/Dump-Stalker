/**
 * @author Flavien Lallemant
 * @file smtp.h
 * @brief SMTP Protocol Header File
 * @ingroup application
 * 
 * This file contains the definition of the SMTP header.
 * It provides functions to check if a packet is a SMTP packet.
 */

#ifndef SMTP_H
#define SMTP_H

#include "types.h"

/**
 * @brief Check if a packet is a SMTP packet
 * 
 * @param packet The packet to check
 * @return 1 if the packet is a SMTP packet, 0 otherwise
 */
int is_smtp(const u_char* packet);

#endif // SMTP_H