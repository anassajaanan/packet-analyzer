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


void init_connection_tracker() {
    memset(hash_table, 0, sizeof(hash_table));
}