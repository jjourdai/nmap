
#include "nmap.h"

void 	init_iphdr(struct iphdr *ip, uint32_t dest)
{
	ft_bzero(ip, sizeof(*ip));
	ip->version = 4;
	ip->ihl = sizeof(struct ip) >> 2;
	ip->tos = 0;
	ip->tot_len = htons(sizeof(struct buffer));
	ip->id = getpid();
	ip->frag_off = 0;
	ip->ttl = 0;
	ip->protocol = IPPROTO_TCP;
	ip->check = 0;
	ip->daddr = dest;
	ip->saddr = 0;
}

void	init_icmphdr(struct icmphdr *icmp)
{
	ft_bzero(icmp, sizeof(*icmp));
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = getpid();
	icmp->un.echo.sequence = 1;
	icmp->checksum = 0;
}

void	init_udphdr(struct udphdr *udp)
{
	ft_bzero(udp, sizeof(*udp));
	
	udp->source = 0;
	udp->dest = 0;
	udp->len = htons(sizeof(struct buffer) - sizeof(struct iphdr));
	udp->check = 0;
}

void	init_tcphdr(struct tcphdr *tcp)
{
	ft_bzero(tcp, sizeof(*tcp));
	
	tcp->th_sport = htons(256);
	tcp->th_dport = 3500;
	tcp->th_seq = 0;
	tcp->th_ack = 0;
	tcp->th_off = sizeof(struct tcphdr) >> 2;
	tcp->th_flags = TH_SYN;
	tcp->th_win = 0;
	tcp->th_sum = 0;
	tcp->th_urp = 0;
}

/*
void	init_env_socket(char *domain)
{
	ft_memcpy(&env.addrinfo, result_dns(domain), sizeof(struct addrinfo));
	if (((struct sockaddr_in*)env.addrinfo.ai_addr)->sin_addr.s_addr == INADDR_BROADCAST) {
		fprintf(stderr, "Do you want to ping broadcast? but No\n"); exit(EXIT_FAILURE);
	}
	if ((env.soc = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
		perror("socket "); exit(EXIT_FAILURE);
	} else {
		int opt_value = 1;
		if (setsockopt(env.soc, IPPROTO_IP, IP_HDRINCL, &opt_value, sizeof(opt_value)) < 0) {
			perror("setsockopt"); exit(EXIT_FAILURE);
		}
	}
}


void	init_receive_buffer(void)
{
	static struct iovec target;

	target.iov_base = &env.to_recv;
	target.iov_len = sizeof(env.to_recv);
	env.msg.msg_iov = &target;
	env.msg.msg_iovlen = 1;
}
*/
