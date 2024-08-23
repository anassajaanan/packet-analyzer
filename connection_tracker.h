#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include <stdint.h>
#include <time.h>

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
void process_tcp_packet(struct pcap_pkthdr *header, const struct ip *ip_header, const struct tcphdr *tcp_header);


#endif // CONNECTION_TRACKER_H