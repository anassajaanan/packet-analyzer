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



void process_tcp_packet(struct pcap_pkthdr *header, const struct ip *ip_header, const struct tcphdr *tcp_header)
{
    connection_info *conn = find_or_create_connection(
        ip_header->ip_src.s_addr, ip_header->ip_dst.s_addr,
        ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport)
    );

    if (!conn) return;

    if (conn->packets_in == 0 && conn->packets_out == 0) {
        conn->start_time.tv_sec = header->ts.tv_sec;
        conn->start_time.tv_nsec = header->ts.tv_usec * 1000;
    }
    
	conn->last_time.tv_sec = header->ts.tv_sec;
    conn->last_time.tv_nsec = header->ts.tv_usec * 1000;

    if (tcp_header->th_flags & TH_SYN) {
        conn->packets_out++;
    } else if (tcp_header->th_flags & (TH_FIN | TH_RST)) {
        conn->packets_in++;
        conn->is_active = 0;
    }
}


void cleanup_connections()
{
    for (int i = 0; i < HASH_SIZE; i++) {
        hash_entry **pp = &hash_table[i];
        while (*pp) {
            hash_entry *entry = *pp;
            if (!entry->info.is_active) {
                double duration = difftime(entry->info.last_time.tv_sec, entry->info.start_time.tv_sec);

                printf("Connection closed: %s:%d -> %s:%d\n",
                       inet_ntoa((struct in_addr){entry->info.src_ip}),
                       entry->info.src_port,
                       inet_ntoa((struct in_addr){entry->info.dst_ip}),
                       entry->info.dst_port);
                printf("  Duration: %.3f seconds\n", duration);
                printf("  Packets IN: %u, OUT: %u\n", entry->info.packets_in, entry->info.packets_out);

                *pp = entry->next;
                free(entry);
            } else {
                pp = &entry->next;
            }
        }
    }
}


void free_connection_tracker()
{
    for (int i = 0; i < HASH_SIZE; i++) {
        hash_entry *entry = hash_table[i];
        while (entry) {
            hash_entry *next = entry->next;
            free(entry);
            entry = next;
        }
    }
}