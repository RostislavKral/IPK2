#include <iostream>
#include <getopt.h>
#include <pcap.h>



void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    //TODO: catch packet and print it
    int packet_type = ((int) (packet[12]) << 8) | (int) packet[13];

    // std::cout << packet_type << std::endl;

    char source_ip[256];
    char destination_ip[256];
    u_char * packethdr = const_cast<u_char *>(packet);

    struct ip* iphdr;

    printf("%d\n", packet_type);

}





int main() {
    //std::cout << "Hello, World!" << std::endl;

    char err[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = ""; //TODO: getopt for protocols and stuuff
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