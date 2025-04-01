#include "pcap-test.h"

void parse_ethernet(struct libnet_ethernet_hdr *ethernet)
{
    printf("src mac address: %02x:%02x:%02x:%02x:%02x:%02x\n", \
        ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], \
        ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
    printf("dst mac address: %02x:%02x:%02x:%02x:%02x:%02x\n", \
        ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], \
        ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
}

void parse_ipv4(struct libnet_ipv4_hdr *ipv4)
{
    struct in_addr src = ipv4->ip_src;
    struct in_addr dst = ipv4->ip_dst;

    printf("src ip address: %s\n", inet_ntoa(src));
    printf("dst ip address: %s\n", inet_ntoa(dst));
}

void parse_tcp(struct libnet_tcp_hdr *tcp)
{
    printf("src tcp port: %u\n", ntohs(tcp->th_sport));
    printf("dst tcp port: %u\n", ntohs(tcp->th_dport));
}