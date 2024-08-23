#include "connection_tracker.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

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