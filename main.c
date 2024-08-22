#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include "queue.h"
#include <signal.h>


typedef struct {
    t_queue *queue;
    pcap_t *handle;
    char *filename;
} thread_data;

#define PACKET_BUFFER_SIZE 65535


volatile sig_atomic_t keep_running = 1;

void sigint_handler(int sig)
{
    keep_running = 0;
}

void get_packet_info(const u_char *packet, struct pcap_pkthdr packet_header, t_queue *queue) {

	t_packet *new_packet = (t_packet *)malloc(sizeof(t_packet));
    if (new_packet == NULL) {
        fprintf(stderr, "Failed to allocate memory for new packet\n");
        return;
    }

    printf("\n\nPacket capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
    
    // Ethernet header
    struct ether_header *eth_header = (struct ether_header *) packet;
    snprintf(new_packet->src_mac, MAC_ADDR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
           eth_header->ether_shost[0], eth_header->ether_shost[1],
           eth_header->ether_shost[2], eth_header->ether_shost[3],
           eth_header->ether_shost[4], eth_header->ether_shost[5]);
    snprintf(new_packet->dst_mac, MAC_ADDR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1],
           eth_header->ether_dhost[2], eth_header->ether_dhost[3],
           eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

	printf("Source MAC: %s\n", new_packet->src_mac);
    printf("Destination MAC: %s\n", new_packet->dst_mac);
    
    // IP header
    struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
	strncpy(new_packet->src_ip, inet_ntoa(ip_header->ip_src), IP_ADDR_LEN - 1);
    strncpy(new_packet->dst_ip, inet_ntoa(ip_header->ip_dst), IP_ADDR_LEN - 1);

    printf("Source IP: %s\n", new_packet->src_ip);
    printf("Destination IP: %s\n", new_packet->dst_ip);
    
    // TCP header
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        strncpy(new_packet->protocol, "TCP", PROTOCOL_LEN - 1);
		new_packet->src_port = ntohs(tcp_header->th_sport);
        new_packet->dst_port = ntohs(tcp_header->th_dport);
		
		printf("Protocol: %s\n", new_packet->protocol);
        printf("Source Port: %d\n", new_packet->src_port);
        printf("Destination Port: %d\n", new_packet->dst_port);

        // Check if it's HTTP traffic 
        if (ntohs(tcp_header->th_dport) == 80 || ntohs(tcp_header->th_sport) == 80) {
            
            const char *http_data = (const char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + (tcp_header->th_off * 4));

            
            // Check for HTTP method (GET or POST)
            if (strncmp(http_data, "GET ", 4) == 0)
			{
                strncpy(new_packet->http_method, "GET", HTTP_METHOD_LEN - 1);
            }
			else if (strncmp(http_data, "POST ", 5) == 0)
			{
                strncpy(new_packet->http_method, "POST", HTTP_METHOD_LEN - 1);
            }

			printf("HTTP Method: %s\n", new_packet->http_method);

            // Extract Host header
            const char *host_start = strstr(http_data, "Host: ");
            if (host_start) {
                host_start += 6;
                const char *host_end = strchr(host_start, '\r');
                if (host_end) {
                    int host_len = (int)(host_end - host_start);
					int final_len = host_len < HOST_LEN - 1 ? host_len : HOST_LEN - 1;
                    strncpy(new_packet->host, host_start, final_len);
                    new_packet->host[final_len] = '\0';
                    printf("Host: %s\n", new_packet->host);
                }
            }

			// Extract User Agent
			const char *user_agent_start = strstr(http_data, "User-Agent: ");
			if (user_agent_start) {
				user_agent_start += 12;
				const char *user_agent_end = strchr(user_agent_start, '\r');
				if (user_agent_end) {
					int user_agent_len = (int) (user_agent_end - user_agent_start);
					int final_user_agent_len = user_agent_len < USER_AGENT_LEN - 1 ? user_agent_len : USER_AGENT_LEN - 1;
					strncpy(new_packet->user_agent, user_agent_start, final_user_agent_len);
					new_packet->user_agent[final_user_agent_len] = '\0';
					printf("User-Agent: %s\n", new_packet->user_agent);
				}
			}
        }
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        strncpy(new_packet->protocol, "UDP", PROTOCOL_LEN - 1);
        new_packet->src_port = ntohs(udp_header->uh_sport);
        new_packet->dst_port = ntohs(udp_header->uh_dport);
        
        printf("Protocol: %s\n", new_packet->protocol);
        printf("Source Port: %d\n", new_packet->src_port);
        printf("Destination Port: %d\n", new_packet->dst_port);
    }


	enqueue(queue, new_packet);
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{
	t_queue	*queue = (t_queue *)args;

    get_packet_info(packet_body, *packet_header, queue);
    return;
}






// ./a.out -i interface -o filename.txt
// ./a.out -f fdfdfdfd.pacap -o filename.txt


int handle_command_line(int argc, char *argv[])
{
	if (argc != 5)
	{
		fprintf(stderr, "Usage: %s [-i interface] [-o output.txt]    OR    Usage: %s [-f file.pcap] [-o output.txt]\n", argv[0], argv[0]);
        return -1;
	}

	if ((strcmp(argv[1], "-i") != 0 && strcmp(argv[1], "-f") != 0) || strcmp(argv[3], "-o") != 0)
	{
		fprintf(stderr, "Usage: %s ([-i interface] / [-f file.pcap]) [-o output.txt]\n", argv[0]);
        return -1;
	}
	return 0;
}

pcap_t *get_interface_handler(char *handler_type, char *device)
{
	pcap_t *handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	int timeout_limit = 10000; /* In milliseconds */

	if (strcmp(handler_type, "-i") == 0)
	{
		handle = pcap_open_live(device, PACKET_BUFFER_SIZE, 0, timeout_limit, error_buffer);
		if (handle == NULL) {
			fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
			return NULL;
		}
	}
	else if (strcmp(handler_type, "-f") == 0)
	{
		handle = pcap_open_offline(device, error_buffer);
		if (handle == NULL) {
			fprintf(stderr, "Could not open .pcap file %s: %s\n", device, error_buffer);
			return NULL;
		}
	}
	return handle;
}


int main(int argc, char *argv[]) {

	char *filename;
	t_queue queue;

	if (handle_command_line(argc, argv) != 0)
	{
		exit(EXIT_FAILURE);
	}

	filename = argv[4];

	pcap_t *handle = get_interface_handler(argv[1], argv[2]);
	if (handle == NULL)
	{
		exit(EXIT_FAILURE);
	}

	

	init_queue(&queue);

	signal(SIGINT, sigint_handler);


    while (keep_running && (pcap_dispatch(handle, -1, my_packet_handler, (u_char *)&queue) >= 0));

	printf("Cleaning up...\n");
    while (!queue_is_empty(&queue)) {
        t_packet *packet = dequeue(&queue);
        // Process or log the packet if needed
        free(packet);
    }

	pcap_close(handle);



    return 0;
}

