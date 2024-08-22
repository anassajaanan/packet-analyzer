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
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
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

