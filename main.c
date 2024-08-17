#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>

void print_usage(const char *progname) {
    printf("Usage: %s <pcap file> [--srcaddr <src_ip>] [--dstaddr <dst_ip>] [--srcport <src_port>] [--dstport <dst_port>]\n", progname);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *pcap_file = argv[1];
    char *src_ip = NULL, *dst_ip = NULL;
    int src_port = -1, dst_port = -1;

    // Парсинг аргументов командной строки
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--srcaddr") == 0 && i + 1 < argc) {
            src_ip = argv[++i];
        } else if (strcmp(argv[i], "--dstaddr") == 0 && i + 1 < argc) {
            dst_ip = argv[++i];
        } else if (strcmp(argv[i], "--srcport") == 0 && i + 1 < argc) {
            src_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--dstport") == 0 && i + 1 < argc) {
            dst_port = atoi(argv[++i]);
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    // Открываем pcap файл
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int total_packets = 0, tcp_packets = 0, filtered_tcp_packets = 0;

    // Чтение пакетов
    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        total_packets++;

        struct ip *ip_hdr = (struct ip *)(packet + 14); // Ethernet header is 14 bytes
        if (ip_hdr->ip_p == IPPROTO_TCP) {
            tcp_packets++;

            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + 14 + (ip_hdr->ip_hl * 4));
            int packet_src_port = ntohs(tcp_hdr->th_sport);
            int packet_dst_port = ntohs(tcp_hdr->th_dport);

            char packet_src_ip[INET_ADDRSTRLEN], packet_dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_hdr->ip_src), packet_src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_hdr->ip_dst), packet_dst_ip, INET_ADDRSTRLEN);

            int match = 1;
            if (src_ip && strcmp(src_ip, packet_src_ip) != 0) match = 0;
            if (dst_ip && strcmp(dst_ip, packet_dst_ip) != 0) match = 0;
            if (src_port != -1 && src_port != packet_src_port) match = 0;
            if (dst_port != -1 && dst_port != packet_dst_port) match = 0;

            if (match) {
                filtered_tcp_packets++;

                // Вывод времени и информации о пакете, включая порядковый номер
                time_t packet_time = header->ts.tv_sec;
                struct tm *ltime = localtime(&packet_time);
                char time_string[16];
                strftime(time_string, sizeof time_string, "%H:%M:%S", ltime);
                printf("Packet #%d matched: Time: %s, Src IP: %s, Dst IP: %s, Src Port: %d, Dst Port: %d\n",
                       total_packets, time_string, packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port);
            }
        }
    }

    pcap_close(handle);

    // Вывод результатов
    printf("Total packets: %d\n", total_packets);
    printf("TCP packets: %d\n", tcp_packets);
    printf("Filtered TCP packets: %d\n", filtered_tcp_packets);

    return 0;
}

