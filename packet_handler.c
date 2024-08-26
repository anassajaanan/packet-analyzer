#include "packet_handler.h"
#include "connection_tracker.h"


void get_packet_info(const u_char *packet, struct pcap_pkthdr packet_header, t_queue *queue) {

	t_packet *new_packet = (t_packet *)malloc(sizeof(t_packet));
    if (new_packet == NULL) {
        fprintf(stderr, "Failed to allocate memory for new packet\n");
        return;
    }

	memset(new_packet, 0, sizeof(t_packet));

    // printf("\n\nPacket capture length: %d\n", packet_header.caplen);
    // printf("Packet total length %d\n", packet_header.len);
    
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

    
    // IP header
    struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
	strncpy(new_packet->src_ip, inet_ntoa(ip_header->ip_src), IP_ADDR_LEN - 1);
    strncpy(new_packet->dst_ip, inet_ntoa(ip_header->ip_dst), IP_ADDR_LEN - 1);

    // printf("Source IP: %s\n", new_packet->src_ip);
    // printf("Destination IP: %s\n", new_packet->dst_ip);
    
    // TCP header
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        strncpy(new_packet->protocol, "TCP", PROTOCOL_LEN - 1);
		new_packet->src_port = ntohs(tcp_header->th_sport);
        new_packet->dst_port = ntohs(tcp_header->th_dport);
		
		// printf("Protocol: %s\n", new_packet->protocol);
        // printf("Source Port: %d\n", new_packet->src_port);
        // printf("Destination Port: %d\n", new_packet->dst_port);

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

			// printf("HTTP Method: %s\n", new_packet->http_method);

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
                    // printf("Host: %s\n", new_packet->host);
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
					// printf("User-Agent: %s\n", new_packet->user_agent);
				}
			}
        }


		// start Tracking this TCP connection
		process_tcp_packet(&packet_header, ip_header, tcp_header);

    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        strncpy(new_packet->protocol, "UDP", PROTOCOL_LEN - 1);
        new_packet->src_port = ntohs(udp_header->uh_sport);
        new_packet->dst_port = ntohs(udp_header->uh_dport);
        
        // printf("Protocol: %s\n", new_packet->protocol);
        // printf("Source Port: %d\n", new_packet->src_port);
        // printf("Destination Port: %d\n", new_packet->dst_port);
    }


	enqueue(queue, new_packet);
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{
	t_queue	*queue = (t_queue *)args;

    get_packet_info(packet_body, *packet_header, queue);
    return;
}


