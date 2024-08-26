
#include "global.h"
#include "packet_handler.h"
#include "threads_handler.h"
#include "connection_tracker.h"
#include <signal.h>



pcap_t *handle = NULL;

volatile sig_atomic_t keep_running = 1;

void sigint_handler(int sig)
{
	(void)sig;
    keep_running = 0;

	// Break pcap_dispatch loop
    pcap_breakloop(handle);
}


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
	pcap_t *handle = NULL;
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
	pthread_t capture_tid, write_tid;

	if (handle_command_line(argc, argv) != 0)
	{
		exit(EXIT_FAILURE);
	}

	filename = argv[4];

	handle = get_interface_handler(argv[1], argv[2]);
	if (handle == NULL)
	{
		exit(EXIT_FAILURE);
	}

	

	init_queue(&queue);

	// signal(SIGINT, sigint_handler);

	thread_data data = {
        .queue = &queue,
        .handle = handle,
        .filename = filename,
        .keep_running = &keep_running
    };

	// Set up signal handling
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);

	// Create threads
    pthread_create(&capture_tid, NULL, capture_packets_thread, &data);
    pthread_create(&write_tid, NULL, write_thread, &data);


	// Wait for threads to finish
    pthread_join(capture_tid, NULL);
    pthread_join(write_tid, NULL);



	printf("Cleaning up...\n");

	// Add cleanup_connections here
    cleanup_connections();

    free_queue(&queue);
	free_connection_tracker();

	pcap_close(handle);
    return 0;
}

