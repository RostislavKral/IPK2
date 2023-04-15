#include <iostream>
#include <getopt.h>
#include <pcap.h>

void print_packet_data(const u_char *packet, int length) {
    int i, j;
    const u_char *byte;

    for (i = 0; i < length; i += 16) {
        printf("0x%04x: ", i);

        byte = packet + i;

        // Print hexadecimal values for this row
        for (j = 0; j < 16; j++) {
            if (i + j < length) {
                printf("%02x ", byte[j]);
            } else {
                printf("   ");
            }
        }

        printf("  ");

        // Print ASCII values for this row
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

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    //TODO: catch packet and print it
    int packet_type = ((int) (packet[12]) << 8) | (int) packet[13];

    // std::cout << packet_type << std::endl;

    char source_ip[256];
    char destination_ip[256];
    u_char * packethdr = const_cast<u_char *>(packet);

    struct ip* iphdr;

    print_packet_data(packet, header->len);

}





int main() {
    //std::cout << "Hello, World!" << std::endl;

    char err[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ndp"; //TODO: getopt for protocols and stuuff
    bpf_u_int32 net;
    bpf_u_int32 source_ip, netmask;
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handler;


    handler = pcap_open_live("enp31s0", BUFSIZ, 1, 1000, err);


    pcap_compile(handler, &fp, filter_exp, 0, net);
    // exit(0);

    pcap_lookupnet("enp31s0", &source_ip, &netmask, errbuff);
    std::cout << source_ip << std::endl;

    int datalink = pcap_datalink(handler);
    std::cout << datalink << std::endl;



    pcap_setfilter(handler, &fp);

    pcap_loop(handler, 100, process_packet, nullptr);
    pcap_close(handler);

    /*= pcap_create("enp31s0",err);
    std::cout << pcap_var << std::endl;*/
    return 0;
}