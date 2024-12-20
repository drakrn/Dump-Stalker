/**
 * @author Flavien Lallemant
 * @file ethernet.h
 * @brief Ethernet layer
 * @ingroup data_link
 * 
 * This file contains the definition of the Ethernet layer.
 * It provides the function to handle Ethernet frames.
 */

#ifndef ETHERNET_H
#define ETHERNET_H

#if 0
/* Only to fix intellisense being dumb */
#define __USE_MISC 1
#endif

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include "types.h"


/**
 * @brief Handle an Ethernet frame
 * 
 * This function handles an Ethernet frame.
 * 
 * @param packet The packet to handle
 * @return int 0 if the packet is well handled, -1 otherwise
 */
int cast_ethernet(const u_char* packet);    /* Get ethernet frame from packet then handle the ethernet type */

#endif // ETHERNET_H