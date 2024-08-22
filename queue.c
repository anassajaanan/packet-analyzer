
#include <queue.h>
#include <stdlib.h>
#include <stdio.h>

void	init_queue(t_queue *q)
{
	q->front = NULL;
	q->rear = NULL;
}

void	enqueue(t_queue *q, t_packet *packet)
{
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
}

t_packet *dequeue(t_queue *q)
{
	t_packet			*packet;
	struct s_queue_node	*tmp;

	tmp = q->front;
	q->front = q->front->next;
	packet = tmp->packet;
	free(tmp);
	return (packet);
}

int	queue_is_empty(t_queue *q)
{
	if (q->front == NULL)
		return (1);
	return (0);
}