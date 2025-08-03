#include "arphdr.h"

uint8_t* stringip_to_byteip(char* str_ip){
	uint8_t byte_ip[4] = {0,0,0,0};
	sscanf(str_ip,
        "%u.%u.%u.%u",
        &byte_ip[3], &byte_ip[2], &byte_ip[1], &byte_ip[0]
    );
	return byte_ip;
}

char* byteip_to_stringip(uint8_t* byte_ip){
    char str_ip[16] = {0};
    sprintf(str_ip,
        "%u.%u.%u.%u",
        byte_ip[3], byte_ip[2], byte_ip[1], byte_ip[0]
    );
    return str_ip;
}