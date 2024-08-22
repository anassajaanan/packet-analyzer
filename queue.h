
#ifndef QUEUE_H
#define QUEUE_H


#include <pthread.h>

struct t_packet;



#define MAC_ADDR_LEN 18
#define IP_ADDR_LEN 16
#define PROTOCOL_LEN 8
#define HTTP_METHOD_LEN 8
#define HOST_LEN 256
#define USER_AGENT_LEN 256


typedef struct s_queue_node
{
    
	struct t_packet			*packet;
    struct s_queue_node		*next;
} t_queue_node;



typedef struct s_queue
{
	t_queue_node	*front;
	t_queue_node	*rear;
	pthread_mutex_t mutex;
}						t_queue;

//  QUEUE
void			init_queue(t_queue *q);
void			enqueue(t_queue *q, struct t_packet *packet);
struct t_packet	*dequeue(t_queue *q);
int				queue_is_empty(t_queue *q);
void			free_queue(t_queue *q);



#endif // QUEUE_H