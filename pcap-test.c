#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void print_ip_address(struct in_addr ip) {
	// inet_ntoa : Convert Internet number in IN to ASCII representation. 
	// The return value is a pointer to an internal array containing the string.

	printf("%s", inet_ntoa(ip));

	return;
}

void print_mac_address(uint8_t *mac) {
	for (int i = 0; i < 6; i++) {
		printf("%02x", mac[i]);
		if (i != 5) {
			printf(":");
		}
	}

	return;
}

void print_port_number(uint16_t port) {
	printf("%5d", ntohs(port));

	return;
}

void print_eth_info(struct libnet_ethernet_hdr *ethernet_header) {
	print_mac_address(ethernet_header->ether_shost);
	printf("\t");
	print_mac_address(ethernet_header->ether_dhost);
	printf("\t");

	return;
}

void print_ip_info(struct libnet_ipv4_hdr *ipv4_header) {
	print_ip_address(ipv4_header->ip_src);
	printf("\t");
	print_ip_address(ipv4_header->ip_dst);
	printf("\t");
	
	return;
}

void print_tcp_info(struct libnet_tcp_hdr *PCKT_TCP_HDR) {
	print_port_number(PCKT_TCP_HDR->th_sport);
	printf("\t\t");
	print_port_number(PCKT_TCP_HDR->th_dport);
	printf("\t\t");

	return;
}

void print_data_info(const uint8_t *packet, uint8_t packet_data_offset, uint8_t packet_data_length) {

	if (packet_data_length == 0) {
		printf("empty");
	}

	if (packet_data_length > 8) {
		packet_data_length = 8; // print only 8 bytes of data
	}

	for (int i = packet_data_offset; i < packet_data_offset + packet_data_length; i++) {
		printf("%02x ", packet[i]);
	}

	return;
}


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	// print header
	printf("source_mac\t\tdestination_mac\t\tsource_IP\tdest_IP\t\tsource_port\tdest_port\tdata\n");

	while (true) {

		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		// get ethernet header
		struct libnet_ethernet_hdr *ethernet_header = (struct libnet_ethernet_hdr *)packet;

		// only dump packets using IP
		uint16_t packet_ethernet_type = ntohs(ethernet_header->ether_type);
		if (packet_ethernet_type != ETHERTYPE_IP) continue;

		// get ipv4 header
		struct libnet_ipv4_hdr *ipv4_header = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));

		// only dump packets using TCP
		uint16_t packet_ip_protocol_type = ipv4_header->ip_p;
		if (packet_ip_protocol_type != IPPROTO_TCP) continue;

		// get tcp header
        struct libnet_tcp_hdr *tcp_header = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + (ipv4_header->ip_hl << 2));
		uint8_t packet_data_offset = sizeof(struct libnet_ethernet_hdr) + (ipv4_header->ip_hl << 2) + (tcp_header->th_off << 2);

		uint8_t packet_data_length = ntohs(ipv4_header->ip_len) - (ipv4_header->ip_hl << 2) - (tcp_header->th_off << 2);


		print_eth_info(ethernet_header);
		print_ip_info(ipv4_header);
		print_tcp_info(tcp_header);
		print_data_info(packet, packet_data_offset, packet_data_length);
		printf("\n");

	}

	pcap_close(pcap);
}
