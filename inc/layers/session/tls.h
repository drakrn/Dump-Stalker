/**
 * @author Flavien Lallemant
 * @file tls.h
 * @brief TLS layer
 * @ingroup session
 * 
 * This file contains the definition of the TLS layer.
 */

#ifndef TLS_H
#define TLS_H

#include <stdint.h>


/**
 * @brief TLS record layer
 * 
 * This structure represents the TLS record layer.
 */
struct tlshdr {
    uint8_t tls_ct;
    uint16_t tls_lv;
    uint16_t tls_len;
} __attribute__((packed));
#define TLS_V(tls) (((tls)->tls_lv & 0x00FF)) /**< Get the TLS version */

#endif // TLS_H