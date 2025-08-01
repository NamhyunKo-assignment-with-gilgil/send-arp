#pragma once
#include <stdio.h>

typedef struct MY_ETHERNET_HEADER{	/* ethernet_hdr total 14bytes */
    u_int8_t  ether_dhost[6];	/* destination ethernet address */
    u_int8_t  ether_shost[6];	/* source ethernet address */
    u_int16_t ether_type;	/* protocol */
} ETHERNET_HDR;
