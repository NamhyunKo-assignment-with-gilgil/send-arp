#pragma once
#include <stdio.h>
#include <stdint.h>

typedef struct MY_ETHERNET_HEADER{	/* ethernet_hdr total 14bytes */
    uint8_t  ether_dhost[6];	/* destination ethernet address */
    uint8_t  ether_shost[6];	/* source ethernet address */
    uint16_t ether_type;	/* protocol */
} ETHERNET_HDR;

uint8_t* stringmac_to_bytemac(char* str_mac);
char* bytemac_to_stringmac(uint8_t* byte_mac);