#include "ethhdr.h"

u_int8_t* stringmac_to_bytemac(char* str_mac){
    u_int8_t byte_mac[6] = {0, 0, 0, 0, 0, 0};
    sscanf(str_mac,
        "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX",
        &byte_mac[0], &byte_mac[1], &byte_mac[2], &byte_mac[3], &byte_mac[4], &byte_mac[5]
    );
    return byte_mac;
}

char* bytemac_to_stringmac(u_int8_t* byte_mac){
    char str_mac[18] = {0};
    sprintf(str_mac,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        byte_mac[0], byte_mac[1], byte_mac[2], byte_mac[3], byte_mac[4], byte_mac[5]
    );
    return str_mac;
}