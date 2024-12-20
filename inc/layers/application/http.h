/**
 * @author Flavien Lallemant
 * @file http.h
 * @brief HTTP Protocol Header File
 * @ingroup application
 * 
 * This file contains the definition of the HTTP layer.
 * It provides functions to check if a packet is an HTTP packet.
 */

#ifndef HTTP_H
#define HTTP_H

#include "types.h"

/**
 * @brief Check if a packet is an HTTP packet
 * 
 * @param packet The packet to check
 * @return 1 if the packet is an HTTP packet, 0 otherwise
 */
int is_http(const u_char* packet);

#endif // HTTP_H