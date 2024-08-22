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

#define PACKET_BUFFER_SIZE 65535

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("\n\nPacket capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
    
    // Ethernet header
    struct ether_header *eth_header = (struct ether_header *) packet;
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1],
           eth_header->ether_shost[2], eth_header->ether_shost[3],
           eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1],
           eth_header->ether_dhost[2], eth_header->ether_dhost[3],
           eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    
    // IP header
    struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
    
    // TCP header
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        printf("Protocol: TCP\n");
        printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
        printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));

        // Check if it's HTTP traffic 
        if (ntohs(tcp_header->th_dport) == 80 || ntohs(tcp_header->th_sport) == 80) {
            
            const char *http_data = (const char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + (tcp_header->th_off * 4));

            
            // Check for HTTP method (GET or POST)
            if (strncmp(http_data, "GET ", 4) == 0) {
                printf("HTTP Method: GET\n");
            } else if (strncmp(http_data, "POST ", 5) == 0) {
                printf("HTTP Method: POST\n");
            }

            // Extract Host header
            const char *host_start = strstr(http_data, "Host: ");
            if (host_start) {
                host_start += 6;
                const char *host_end = strchr(host_start, '\r');
                if (host_end) {
                    printf("Host: %.*s\n", (int)(host_end - host_start), host_start);
                }
            }

			// Extract User Agent
			const char *user_agent_start = strstr(http_data, "User-Agent: ");
			if (user_agent_start) {
				user_agent_start += 12;
				const char *user_agent_end = strchr(user_agent_start, '\r');
				if (user_agent_end) {
					printf("User-Agent: %.*s\n", (int)(user_agent_end - user_agent_start), user_agent_start);
				}
			}
        }
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        printf("Protocol: UDP\n");
        printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
        printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
    }
}

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)
{
    print_packet_info(packet_body, *packet_header);
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

    pcap_loop(handle, 0, my_packet_handler, NULL);

    return 0;
}

