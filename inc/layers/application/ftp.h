/**
 * @author: Flavien Lallemant
 * @file ftp.h
 * @brief FTP Protocol Header File
 * @ingroup application
 * 
 * This file contains the definition of the FTP layer.
 * It provides functions to check if a packet is an FTP packet.
 */

#ifndef FTP_H
#define FTP_H

#include "types.h"

/**
 * @brief Check if the packet is an FTP packet
 * 
 * @param packet The packet
 * @return int 1 if the packet is an FTP packet, 0 otherwise
 */
int is_ftp(const u_char *packet);

#endif // FTP_H