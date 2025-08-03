#include "arphdr.h"

void stringip_to_byteip(const char* str_ip, uint8_t* byte_ip){
	sscanf(str_ip,
        "%u.%u.%u.%u",
        &byte_ip[3], &byte_ip[2], &byte_ip[1], &byte_ip[0]
    );
}

void byteip_to_stringip(uint8_t* byte_ip, char* str_ip){
    sprintf(str_ip,
        "%u.%u.%u.%u",
        byte_ip[3], byte_ip[2], byte_ip[1], byte_ip[0]
    );
}