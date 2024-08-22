#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include "queue.h"

#define MAC_ADDR_LEN 18
#define IP_ADDR_LEN 16
#define PROTOCOL_LEN 8
#define HTTP_METHOD_LEN 8
#define HOST_LEN 256
#define USER_AGENT_LEN 256

#define PACKET_BUFFER_SIZE 65535



typedef struct {
    char src_mac[MAC_ADDR_LEN];
    char dst_mac[MAC_ADDR_LEN];
    char src_ip[IP_ADDR_LEN];
    char dst_ip[IP_ADDR_LEN];
    char protocol[PROTOCOL_LEN];
    uint16_t src_port;
    uint16_t dst_port;
    char http_method[HTTP_METHOD_LEN];
    char host[HOST_LEN];
    char user_agent[USER_AGENT_LEN];

} t_packet;


void get_packet_info(const u_char *packet, struct pcap_pkthdr packet_header, t_queue *queue);
void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body);


#endif