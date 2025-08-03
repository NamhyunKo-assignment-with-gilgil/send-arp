#include "arphdr.h"

u_int8_t* stringip_to_byteip(char* str_ip){
	u_int8_t byte_ip[4] = {0,0,0,0};
	sscanf(str_ip,
        "%u.%u.%u.%u",
        &byte_ip[3], &byte_ip[2], &byte_ip[1], &byte_ip[0]
    );
	return byte_ip;
}

char* byteip_to_stringip(u_int8_t* byte_ip){
    char str_ip[16] = {0};
    sprintf(str_ip,
        "%u.%u.%u.%u",
        byte_ip[3], byte_ip[2], byte_ip[1], byte_ip[0]
    );
    return str_ip;
}