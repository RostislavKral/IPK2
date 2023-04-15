#include <iostream>
#include <getopt.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <time.h>
#include <stdlib.h>


void print_packet_data(const u_char *packet, int length) {
    int i, j;

    const u_char *byte;

    for (i = 0; i < length; i += 16) {
        printf("0x%04x: ", i);

        byte = packet + i;

        for (j = 0; j < 16; j++) {
            if (i + j < length) {
                printf("%02x ", byte[j]);
            } else {
                printf("   ");
            }
        }

        printf("  ");

        for (j = 0; j < 16; j++) {

            if (i + j < length) {
                if (byte[j] >= 32 && byte[j] <= 126) {
                    printf("%c", byte[j]);
                } else {
                    printf(".");
                }
            } else {
                printf(" ");
            }
        }

        printf("\n");
    }
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    //TODO: catch packet and print it

    //Getting timestamp from packet header
    char timestamp_str[30];
    time_t timestamp = header->ts.tv_sec;
    struct tm tm = *gmtime(&timestamp); // Convert it
    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%dT%H:%M:%S.%06ldZ", &tm); // Converting RFC-3339 timestamp to a string

    printf("timestamp: %s\n", timestamp_str);

    struct ether_header *ethernet_header = (struct ether_header*) packet; //Get ethernet header in order to get MAC address from both, sender and receiver


    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header->ether_shost[0],
           ethernet_header->ether_shost[1],
           ethernet_header->ether_shost[2],
           ethernet_header->ether_shost[3],
           ethernet_header->ether_shost[4],
           ethernet_header->ether_shost[5]);


    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header->ether_dhost[0],
           ethernet_header->ether_dhost[1],
           ethernet_header->ether_dhost[2],
           ethernet_header->ether_dhost[3],
           ethernet_header->ether_dhost[4],
           ethernet_header->ether_dhost[5]);


    printf("frame length: %d bytes\n", header->len); // Already in bytes, we do not have to convert it

    const u_char *payload = packet + sizeof(struct ether_header); // Get payload aka data

    switch (ntohs(ethernet_header->ether_type)) {
        case ETHERTYPE_IP: {
            struct ip *ip_header = (struct ip *) payload;
            char src_ip[INET6_ADDRSTRLEN];
            char dst_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_header->ip_src, src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip, INET_ADDRSTRLEN);
            printf("src IP: %s\n", src_ip);
            printf("dst IP: %s\n", dst_ip);

            switch (ip_header->ip_p) {
                case IPPROTO_TCP: {
                    struct tcphdr *tcp_header = (struct tcphdr *) (payload + (ip_header->ip_hl * 4));
                    printf("TCP packet\n");
                    printf("src port: %d\n", ntohs(tcp_header->th_sport));
                    printf("dst port: %d\n", ntohs(tcp_header->th_dport));
                    break;
                }
                case IPPROTO_UDP: {
                    struct udphdr *udp_header = (struct udphdr *) (payload + (ip_header->ip_hl * 4));
                    printf("UDP packet\n");
                    printf("src port: %d\n", ntohs(udp_header->uh_sport));
                    printf("dst port: %d\n", ntohs(udp_header->uh_dport));
                    break;
                }
                default: {
                    //TODO: I guess nothing should be done in this case
                    break;
                }
            }
            break;
        }
        case ETHERTYPE_IPV6: {

            struct ip6_hdr *ip6_header = (struct ip6_hdr *) payload;
            char dst_ip[INET6_ADDRSTRLEN];
            char src_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN);
            printf("src IP: %s\n", src_ip);
            printf("dst IP: %s\n", dst_ip);
            break;
        }

        case ETHERTYPE_ARP: {
            //TODO: Need to get ARP IP info
            break;
        }
    }
    print_packet_data(packet, header->len);
    printf("\n");

}





int main() {
    char err[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = ""; //TODO: getopt for protocols and stuuff
    //TODO: We need to create a filter string based on data got from getopt
    bpf_u_int32 net;
    bpf_u_int32 source_ip, netmask;
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handler;


    handler = pcap_open_live("wlp2s0", BUFSIZ, 1, 1000, err);

    //TODO: Error handling and SIGINT handler
    pcap_compile(handler, &fp, filter_exp, 0, net);

    pcap_lookupnet("wlp2s0", &source_ip, &netmask, errbuff);

    pcap_setfilter(handler, &fp);

    pcap_loop(handler, 100, process_packet, nullptr);
    pcap_close(handler);

    return 0;
}