


#include <netinet/in.h>
#include <stdlib.h>


#define MAC_ADDR_LEN 18
#define IP_ADDR_LEN 16
#define PROTOCOL_LEN 8
#define HTTP_METHOD_LEN 8
#define HOST_LEN 256
#define USER_AGENT_LEN 256


typedef struct s_packet {

	char src_mac[MAC_ADDR_LEN];
    char dst_mac[MAC_ADDR_LEN];
    char src_ip[IP_ADDR_LEN];
    char dst_ip[IP_ADDR_LEN];
    char protocol[PROTOCOL_LEN];
    uint16_t src_port;
    uint16_t dst_port;
    char http_method[HTTP_METHOD_LEN];
    char host[HOST_LEN];
    char user_agent[USER_AGENT_LEN];

} t_packet;

typedef struct s_queue_node
{
    
	t_packet			*packet;
    struct s_queue_node *next;
} t_queue_node;



typedef struct s_queue
{
	t_queue_node	*front;
	t_queue_node	*rear;
}						t_queue;

//  QUEUE
void		init_queue(t_queue *q);
void		enqueue(t_queue *q, t_packet *packet);
t_packet	*dequeue(t_queue *q);
int			queue_is_empty(t_queue *q);