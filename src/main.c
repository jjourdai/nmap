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

int main(int argc, char **argv)
{
	is_root();
	get_options(argc, argv);
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
