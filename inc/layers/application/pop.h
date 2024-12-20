/**
 * @author Flavien Lallemant
 * @file pop.h
 * @brief POP Protocol Header File
 * @ingroup application
 * 
 * This file contains the definition of the POP layer.
 * It provides functions to check if a packet is a POP packet.
 */

#ifndef POP_H
#define POP_H

#include "types.h"

/**
 * @brief Check if a packet is a POP packet
 * 
 * @param packet The packet to check
 * @return 1 if the packet is a POP packet, 0 otherwise
 */
int is_pop(const u_char *packet);

#endif // POP_H