#ifndef PCAP_TEST_H
# define PCAP_TEST_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <arpa/inet.h> 
#include <stdbool.h>

typedef struct {
	char* dev_;
} Param;

extern Param param;

void parse_ethernet(struct libnet_ethernet_hdr *ethernet);
void parse_ipv4(struct libnet_ipv4_hdr *ipv4);
void parse_tcp(struct libnet_tcp_hdr *tcp);

#endif