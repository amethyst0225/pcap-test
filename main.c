#include "pcap-test.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

Param param = {
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

int main(int argc, char *argv[]) 
{
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

	if (pcap == NULL)
	{
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
    }

	while(true)
	{
		struct pcap_pkthdr *header;
		const u_char *packet;
        struct libnet_ethernet_hdr *ethernet;
        struct libnet_ipv4_hdr *ipv4;
        struct libnet_tcp_hdr *tcp;

   		int res = pcap_next_ex(pcap, &header, &packet);

		if (res == 0) //timeout
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) 
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		printf("%u bytes captured\n", header->caplen);
	
		ethernet = (struct libnet_ethernet_hdr *)packet;
		parse_ethernet(ethernet);

		ipv4 = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
		parse_ipv4(ipv4);
		uint32_t ip_header_len = ipv4->ip_hl * 4; //4byte count -> byte count 
		
		tcp = (struct libnet_tcp_hdr *)((u_char *)ipv4 + ip_header_len);
		parse_tcp(tcp);
		uint32_t tcp_header_len = tcp->th_off * 4; //4byte count -> byte count 
		
		uint32_t header_len = sizeof(struct libnet_ethernet_hdr) + ip_header_len + tcp_header_len;
		uint32_t data_len = header->caplen > header_len ? header->caplen - header_len : 0;
		
		//print data
		printf("Data: ");
        for (uint32_t i = 0; i < data_len && i < 20; i++)
			printf("0x%02X ", packet[header_len + i]);

        printf("\n\n");
	}

	pcap_close(pcap);
    
    return 0;
}
