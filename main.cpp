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
#include <unistd.h>
#include <string.h>


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
    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%dT%H:%M:%S.%06ldZ",
             &tm); // Converting RFC-3339 timestamp to a string

    printf("timestamp: %s\n", timestamp_str);

    struct ether_header *ethernet_header = (struct ether_header *) packet; //Get ethernet header in order to get MAC address from both, sender and receiver


    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header->ether_shost[0], ethernet_header->ether_shost[1],
           ethernet_header->ether_shost[2], ethernet_header->ether_shost[3], ethernet_header->ether_shost[4],
           ethernet_header->ether_shost[5]);


    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header->ether_dhost[0], ethernet_header->ether_dhost[1],
           ethernet_header->ether_dhost[2], ethernet_header->ether_dhost[3], ethernet_header->ether_dhost[4],
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
                    printf("src port: %d\n", ntohs(tcp_header->th_sport));
                    printf("dst port: %d\n", ntohs(tcp_header->th_dport));
                    break;
                }
                case IPPROTO_UDP: {
                    struct udphdr *udp_header = (struct udphdr *) (payload + (ip_header->ip_hl * 4));
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


void getAvailableInterfaces() {
    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_if_t *all_devices;

    if (pcap_findalldevs(&all_devices, error_buffer) != 0) {
        std::cerr << "Error finding devices: " << error_buffer << std::endl;
        exit(-1);
    }

    for (pcap_if_t *device = all_devices; device != nullptr; device = device->next) {
        std::cout << device->name << std::endl;
    }

    pcap_freealldevs(all_devices);
}

void usage() {
    std::cout
            << "Usage: ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--ndp] [--igmp] [--mld] {-n num}"
            << std::endl;
}

int main(int argc, char *argv[]) {
    char err[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    std::string filter = "";
    bpf_u_int32 net;
    bpf_u_int32 source_ip, netmask;
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handler;
    // char* interface = nullptr;
    bool tcp = false;
    bool udp = false;
    bool arp = false;
    bool icmp4 = false;
    bool icmp6 = false;
    bool igmp = false;
    bool mld = false;
    int n = -1;
    int port = 0;
    int opt;
    char *interface = nullptr;

    if (argc == 1) {
        getAvailableInterfaces();
        return 0;
    } else if (argc == 2) {
        const option long_options[] = {{"interface", no_argument, nullptr, 'i'},
                                       {nullptr,     0,           nullptr, 0}};
        while ((opt = getopt_long(argc, argv, "i", long_options, nullptr)) != -1) {
            switch (opt) {
                case 'i':
                    getAvailableInterfaces();
                    break;
                default:
                    usage();
                    exit(-1);
            }
        }

        return 0;
    } else {


        const option long_options[] = {{"interface", required_argument, nullptr, 'i'},
                                       {"tcp",       no_argument,       nullptr, 't'},
                                       {"udp",       no_argument,       nullptr, 'u'},
                                       {"arp",       no_argument,       nullptr, 'a'},
                                       {"icmp4",     no_argument,       nullptr, '4'},
                                       {"icmp6",     no_argument,       nullptr, '6'},
                                       {"igmp",      no_argument,       nullptr, 'g'},
                                       {"mld",       no_argument,       nullptr, 'm'},
                                       {"port",      required_argument, nullptr, 'p'},
                                       {nullptr,     0,                 nullptr, 0}};

        while ((opt = getopt_long(argc, argv, "i:p:tun:", long_options, nullptr)) != -1) {
            switch (opt) {
                case 'i':
                    interface = optarg;
                    break;
                case 'p':
                    port = atoi(optarg);
                    break;
                case 'n':
                    n = atoi(optarg);
                    break;
                case 't':
                    tcp = true;
                    break;
                case 'u':
                    udp = true;
                    break;
                case 'a':
                    arp = true;
                    break;
                case '4':
                    icmp4 = true;
                    break;
                case '6':
                    icmp6 = true;
                    break;
                case 'g':
                    igmp = true;
                    break;
                case 'm':
                    mld = true;
                    break;
                default:
                    usage();
                    return -1;
            }
        }

        if (interface == nullptr || port == -1) {
            usage();
            return -1;
        }

        if (!tcp && !udp && port > 0) {
            usage();
            return -1;
        }

        return 0;
    }


    handler = pcap_open_live("wlp2s0", BUFSIZ, 1, 1, err);
    //TODO: Error handling and SIGINT handler
    pcap_compile(handler, &fp, filter.c_str(), 0, net);

    pcap_lookupnet("wlp2s0", &source_ip, &netmask, errbuff);

    pcap_setfilter(handler, &fp);

    pcap_loop(handler, 100, process_packet, nullptr);
    pcap_close(handler);

    return 0;
}