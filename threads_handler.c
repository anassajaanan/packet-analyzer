#include "threads_handler.h"
#include "global.h"


void *capture_packets_thread(void *arg) {
    thread_data *data = (thread_data *)arg;
    while (keep_running && (pcap_dispatch(data->handle, -1, my_packet_handler, (u_char *)data->queue) >= 0));
    return NULL;
}

void *write_thread(void *arg) {
    thread_data *data = (thread_data *)arg;

    FILE *output_file = fopen(data->filename, "w");
    if (output_file == NULL) {
        fprintf(stderr, "Could not open output file %s\n", data->filename);
        return NULL;
    }

    while (keep_running || !queue_is_empty(data->queue)) {
        if (!queue_is_empty(data->queue)) {
            t_packet *packet = dequeue(data->queue);

            fprintf(output_file, "Source MAC: %s\n", packet->src_mac);
            fprintf(output_file, "Destination MAC: %s\n", packet->dst_mac);
            fprintf(output_file, "Source IP: %s\n", packet->src_ip);
            fprintf(output_file, "Destination IP: %s\n", packet->dst_ip);
            fprintf(output_file, "Protocol: %s\n", packet->protocol);
            fprintf(output_file, "Source Port: %d\n", packet->src_port);
            fprintf(output_file, "Destination Port: %d\n", packet->dst_port);
            fprintf(output_file, "HTTP Method: %s\n", packet->http_method);
            fprintf(output_file, "Host: %s\n", packet->host);
            fprintf(output_file, "User-Agent: %s\n\n", packet->user_agent);

            free(packet);
        }
    }

    fclose(output_file);
    return NULL;
}