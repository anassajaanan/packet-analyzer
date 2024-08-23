
#include "queue.h"
#include "packet_handler.h"

void	init_queue(t_queue *q)
{
	q->front = NULL;
	q->rear = NULL;
	pthread_mutex_init(&q->mutex, NULL);
}

void	enqueue(t_queue *q, struct t_packet *packet)
{
	pthread_mutex_lock(&q->mutex);
	struct s_queue_node	*new_node;

	new_node = (struct s_queue_node *)malloc(sizeof(struct s_queue_node));
	new_node->packet = packet;
	new_node->next = NULL;
	if (q->front == NULL)
	{
		q->front = new_node;
		q->rear = new_node;
	}
	else
	{
		q->rear->next = new_node;
		q->rear = new_node;
	}
	pthread_mutex_unlock(&q->mutex);
}

struct t_packet *dequeue(t_queue *q)
{
	pthread_mutex_lock(&q->mutex);
	t_packet			*packet;
	struct s_queue_node	*tmp;

	tmp = q->front;
	q->front = q->front->next;
	packet = tmp->packet;
	free(tmp);
	pthread_mutex_unlock(&q->mutex);
	return (packet);
}

int	queue_is_empty(t_queue *q)
{
	pthread_mutex_lock(&q->mutex);
	int is_empty = (q->front == NULL);
	pthread_mutex_unlock(&q->mutex);
	return (is_empty);
}


void	free_queue(t_queue *q)
{
	while (!queue_is_empty(q)) {
        t_packet *packet = dequeue(&q);
        free(packet);
    }
	pthread_mutex_destroy(&(q->mutex));
}