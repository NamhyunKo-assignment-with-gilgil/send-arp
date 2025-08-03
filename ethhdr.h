#pragma once
#include <stdio.h>
#include <stdint.h>

typedef struct MY_ETHERNET_HEADER{	/* ethernet_hdr total 14bytes */
    u_int8_t  ether_dhost[6];	/* destination ethernet address */
    u_int8_t  ether_shost[6];	/* source ethernet address */
    u_int16_t ether_type;	/* protocol */
} ETHERNET_HDR;

u_int8_t* stringmac_to_bytemac(char* str_mac);
char* bytemac_to_stringmac(u_int8_t* byte_mac);