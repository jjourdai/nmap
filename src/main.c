#include "nmap.h"
#include "colors.h"

/* sysctl -w net.ipv4.ping_group_range="0 0" */

void	is_root(void)
{
	if (getuid() == 0)
		return ;
	fprintf(stderr, "You must be logged as root\n");
	exit(EXIT_FAILURE);
}

void	run_thread(t_thread_task *task)
{
	uint16_t	port;

	printf("hello, I'm a thread running on [%hu-%hu] :D\n", task->port_range.min, task->port_range.max);
	port = task->port_range.min - 1;
	while (++port < task->port_range.max)
	{
	}
}

int		main(int argc, char **argv)
{
	int		ret;
	size_t	i;

	is_root();

	get_options(argc, argv);

	i = (size_t)-1;
	while (++i < env.flag.thread)
	{
		env.threads[i].port_range.min = env.flag.port_range.min + ((i * (env.flag.port_range.max - env.flag.port_range.min + 1)) / env.flag.thread);
		env.threads[i].port_range.max = env.flag.port_range.min + (((i + 1) * (env.flag.port_range.max - env.flag.port_range.min + 1)) / env.flag.thread) - 1;
		env.threads[i].ports = &env.ports[env.threads[i].port_range.min - env.flag.port_range.min];
		if (!(ret = pthread_create(&env.threads[i].id, NULL, (void *)&run_thread, &env.threads[i])))
			;
	}
	i = (size_t)-1;
	while (++i < env.flag.thread)
		pthread_join(env.threads[i].id, NULL);
/*/
	init_env_socket(env.domain);
	ft_bzero(&env.to_send, sizeof(env.to_send));
	init_iphdr(&env.to_send.ip, &((struct sockaddr_in*)env.addrinfo.ai_addr)->sin_addr);
	init_icmphdr(&env.to_send.icmp);
	init_receive_buffer();
	env.send_packet = 0;
	if (gettimeofday(&env.time, NULL) == -1) {
		perror("gettimeofday "); exit(EXIT_FAILURE);
	}
	loop_exec();
*/
	return (EXIT_SUCCESS);
}
