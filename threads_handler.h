

#ifndef FILE_WRITER_H
#define FILE_WRITER_H

#include "packet_handler.h"




typedef struct {
    t_queue *queue;
    pcap_t *handle;
    char *filename;
} thread_data;


void *capture_packets_thread(void *arg);
void *write_thread(void *arg);

#endif