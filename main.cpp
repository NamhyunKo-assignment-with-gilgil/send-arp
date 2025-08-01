#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1");
}

typedef struct ARP_INFECTION_PACKET {
	ETHERNET_HDR eth_h;
	ARP_HDR arp_h;
} ARP_PACKET;

void get_my_mac()

void receive_arp(int c, char* sender_ip){
	
}

void send_arp(int c, char* sender_ip, char* target_ip){
	ARP_PACKET arp_p;

	// arp_p.eth_h.ether_dhost = ; /* target mac address, victim 의미 */
	// arp_p.eth_h.ether_shost = ;	/* my mac address, 내가 보내는거 */
	// arp_p.eth_h.ether_type = htons(0x0806);

	// arp_p.arp_h.hardware_type = htons(0x0001); /* fixed, 무조건 하드웨어 타입(물리적 주소)은 ethernet, 0x0001 */
	// arp_p.arp_h.protocol_type = htons(0x8000); /* fixed, 무조건 프로토콜 타입은 ipv4, 0x8000 */
	// arp_p.arp_h.hardware_length = 0x06;	/* fixed, 무조건 하드웨어 타입(물리적 주소)은 ethernet, 6바이트 */
	// arp_p.arp_h.protocol_length = 0x04;	/* fixed, 무조건 프로토콜 타입은 ipv4, 4바이트 */
	// arp_p.arp_h.operation = htons(0x0002);	/* 우리는 응답으로 송신 -> 0x0002 */
	// arp_p.arp_h.sender_mac_address = '\x00\x00\x00\x00\x00\x00';
	// arp_p.arp_h.sender_ip_address = htonl(argv[c]);
	// arp_p.arp_h.target_mac_address = '\x00\x00\x00\x00\x00\x00';
	// arp_p.arp_h.target_ip_address = htonl(argv[c+1]);

	// int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	// if (res != 0) {
	// 	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	// }
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	

	pcap_close(pcap);
}
