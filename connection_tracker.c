#include "connection_tracker.h"


#define HASH_SIZE 65536

typedef struct hash_entry {
    connection_info info;
    struct hash_entry *next;
} hash_entry;

static hash_entry *hash_table[HASH_SIZE];


static uint32_t hash_function(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
    return (src_ip ^ dst_ip ^ ((uint32_t)src_port << 16 | dst_port)) % HASH_SIZE;
}


void init_connection_tracker() {
    memset(hash_table, 0, sizeof(hash_table));
}


static connection_info *find_or_create_connection(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
    uint32_t hash = hash_function(src_ip, dst_ip, src_port, dst_port);
    hash_entry *entry = hash_table[hash];

    while (entry) {
        if (entry->info.src_ip == src_ip && entry->info.dst_ip == dst_ip &&
            entry->info.src_port == src_port && entry->info.dst_port == dst_port) {
            return &entry->info;
        }
        entry = entry->next;
    }

    // Create if it doesn't existt
    entry = malloc(sizeof(hash_entry));
    if (!entry) {
        fprintf(stderr, "Failed to allocate memory for new connection\n");
        return NULL;
    }

    memset(entry, 0, sizeof(hash_entry));
    entry->info.src_ip = src_ip;
    entry->info.dst_ip = dst_ip;
    entry->info.src_port = src_port;
    entry->info.dst_port = dst_port;
    entry->info.is_active = 1;

    // Insert at the beginning of the list
    entry->next = hash_table[hash];
    hash_table[hash] = entry;

    return &entry->info;
}


static void remove_connection(connection_info *conn)
{
    uint32_t hash = hash_function(conn->src_ip, conn->dst_ip, conn->src_port, conn->dst_port);
    hash_entry **pp = &hash_table[hash];

    while (*pp) {
        hash_entry *entry = *pp;
        if (&entry->info == conn) {
            *pp = entry->next;
            free(entry);
            return;
        }
        pp = &entry->next;
    }
}



void process_tcp_packet(const struct pcap_pkthdr *header, const struct ip *ip_header, const struct tcphdr *tcp_header)
{

	uint32_t src_ip = ip_header->ip_src.s_addr;
    uint32_t dst_ip = ip_header->ip_dst.s_addr;
    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);


    connection_info *conn = find_or_create_connection(src_ip, dst_ip, src_port, dst_port);

    if (!conn) return;


    // Update packet counts
    if (src_ip == conn->src_ip && src_port == conn->src_port) {
        conn->packets_out++;
    } else {
        conn->packets_in++;
    }

    // Update timestamps
    struct timespec current_time;
    current_time.tv_sec = header->ts.tv_sec;
    current_time.tv_nsec = header->ts.tv_usec * 1000; //convert it to nano secs

    if (conn->packets_in + conn->packets_out == 1) {
        // First packet of the connection
        conn->start_time = current_time;
    }
    conn->last_time = current_time;

    // Check for connection termination
    if (tcp_header->th_flags & (TH_FIN | TH_RST)) {
        long duration_ms = (conn->last_time.tv_sec - conn->start_time.tv_sec) * 1000 +
                           (conn->last_time.tv_nsec - conn->start_time.tv_nsec) / 1000000;

        // Print connection information
        printf("Connection terminated: %s:%d -> %s:%d\n",
               inet_ntoa((struct in_addr){conn->src_ip}),
               conn->src_port,
               inet_ntoa((struct in_addr){conn->dst_ip}),
               conn->dst_port);
        printf("  Duration: %ld milliseconds\n", duration_ms);
        printf("  Packets IN: %u, OUT: %u\n", conn->packets_in, conn->packets_out);

        //mark it innactive
        conn->is_active = 0;

		// remove connection to save some space
		remove_connection(conn);
    }
}



void free_connection_tracker()
{
	printf("function: free_connection_tracker\n");
    for (int i = 0; i < HASH_SIZE; i++) {
        hash_entry *entry = hash_table[i];
        while (entry) {
            hash_entry *next = entry->next;
            free(entry);
            entry = next;
        }
    }
}