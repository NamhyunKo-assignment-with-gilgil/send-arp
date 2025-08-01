#pragma once
#include <stdio.h>

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

void print_sender_mac_address(ARP_HDR* arp){
	for(int i = 0; i < 6; i++){
		printf("%d",arp->sender_mac_address[i]);
		if(i != 5) printf(":");
		else printf("\n");
	}
}

void print_target_mac_address(ARP_HDR* arp){
	for(int i = 0; i < 6; i++){
		printf("%d",arp->target_mac_address[i]);
		if(i != 5) printf(":");
		else printf("\n");
	}
}

void print_sender_ip_address(ARP_HDR* arp){
	for(int i = 0; i < 4; i++){
		printf("%d",arp->sender_ip_address[3 - i]);
		if(i != 3) printf(".");
		else printf("\n");
	}
}

void print_target_ip_address(ARP_HDR* arp){
	for(int i = 0; i < 4; i++){
		printf("%d",arp->target_ip_address[3 - i]);
		if(i != 3) printf(".");
		else printf("\n");
	}
}