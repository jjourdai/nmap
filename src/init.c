
#include "nmap.h"

void 	init_iphdr(struct iphdr *ip, uint32_t dest, uint32_t protocol)
{
	ft_bzero(ip, sizeof(*ip));
	ip->version = 4;
	ip->ihl = sizeof(struct ip) >> 2;
	ip->tos = 0;
	ip->tot_len = htons(sizeof(struct buffer));
	ip->id = env.pid;
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = protocol;
	ip->check = 0;
	ip->daddr = dest;
	ip->saddr = 0;
}

void	init_udphdr(struct udphdr *udp, uint16_t port)
{
	ft_bzero(udp, sizeof(*udp));
	
	udp->source = htons(env.flag.port_src);
	udp->dest = htons(port);
	udp->len = htons(sizeof(struct buffer) - sizeof(struct iphdr));
	udp->check = 0;
}

void	init_tcphdr(struct tcphdr *tcp, uint32_t port, uint32_t flag_type)
{
	ft_bzero(tcp, sizeof(*tcp));
	
	tcp->th_sport = htons(env.flag.port_src);
	tcp->th_dport = htons(port);
	tcp->th_seq = 0;
	tcp->th_ack = 0;
	tcp->th_off = sizeof(struct tcphdr) >> 2;
	tcp->th_flags = flag_type;
	tcp->th_win = 0;
	tcp->th_sum = 0;
	tcp->th_urp = 0;
}
