/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   threads.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: polooo <polooo@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/21 18:40:48 by polooo            #+#    #+#             */
/*   Updated: 2019/04/21 18:41:48 by polooo           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

void	run_thread(t_thread_task *task)
{
	uint16_t	port;
	uint8_t		current_try;
	while (1)
	{
		pthread_cond_wait(&env.cond, &task->mutex);
		current_try = 0;
		for (; current_try < RETRY_MAX; current_try++) {
			port = task->port_range.min - 1;
			while (port < task->port_range.max)
			{
				if (env.response[env.current_scan][port - env.flag.port_range.min + 1] == TIMEOUT)
					send_packet(env.current_scan, port + 1);
				++port;
			}
		}
		alarm(env.timeout);
	}
}

void		create_thread_pool(void)
{
	size_t		i;
	int		ret;

	i = (size_t)-1;
	while (++i < env.flag.thread)
	{
		env.threads[i].mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
		env.threads[i].port_range.min = env.flag.port_range.min + ((i * (env.flag.port_range.max - env.flag.port_range.min + 1)) / env.flag.thread);
		env.threads[i].port_range.max = env.flag.port_range.min + (((i + 1) * (env.flag.port_range.max - env.flag.port_range.min + 1)) / env.flag.thread) - 1;
		if ((ret = pthread_create(&env.threads[i].id, NULL, (void *)&run_thread, &env.threads[i])))
		{
			fprintf(stderr, "cannot create thread\n");
			exit(EXIT_FAILURE);
		}
	}
}

void		remove_thread_pool(void)
{
	size_t		i;

	i = (size_t)-1;
	while (++i < env.flag.thread)
	{
		pthread_cancel(env.threads[i].id);
	}
}
