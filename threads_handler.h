

#ifndef FILE_WRITER_H
#define FILE_WRITER_H

#include "packet_handler.h"
#include "global.h"



typedef struct {
    t_queue *queue;
    pcap_t *handle;
    char *filename;
    volatile sig_atomic_t *keep_running;
} thread_data;


void *capture_packets_thread(void *arg);
void *write_thread(void *arg);

#endif