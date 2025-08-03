#pragma once
#include <iostream>
#include <string>
#include <stdint.h>

typedef struct MY_ARP_HEADER{
	u_int16_t hardware_type;		/* hardware type 16bit */
	u_int16_t protocol_type;		/* protocol type 16bit */
	u_int8_t hardware_length;		/* hardware length 8bit */
	u_int8_t protocol_length;		/* protocol length 8bit */
	u_int16_t operation;			/* operation 16bit */
	u_int8_t sender_mac_address[6];	/* sender mac address 48bit */
	u_int8_t sender_ip_address[4];	/* sender ip address 32bit */
	u_int8_t target_mac_address[6];	/* target mac address 48bit */
	u_int8_t target_ip_address[4];	/* target ip address 32bit */
} ARP_HDR;

u_int8_t* stringip_to_byteip(const char* str_ip);
char* byteip_to_stringip(u_int8_t* byte_ip);