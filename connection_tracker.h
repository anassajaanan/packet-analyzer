#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/time.h>

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    struct timespec start_time;
    struct timespec last_time;
    uint32_t packets_in;
    uint32_t packets_out;
    int is_active;
} connection_info;



void init_connection_tracker();
void process_tcp_packet(const struct pcap_pkthdr *header, const struct ip *ip_header, const struct tcphdr *tcp_header);
void free_connection_tracker();
#endif // CONNECTION_TRACKER_H