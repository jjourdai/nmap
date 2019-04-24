/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   receive.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: polooo <polooo@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/21 17:52:28 by polooo            #+#    #+#             */
/*   Updated: 2019/04/21 19:01:31 by polooo           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"
#include "colors.h"

void	response_tcp(struct buffer *res) 
{
	env.response[env.current_scan][ntohs(res->un.tcp.th_sport) - env.flag.port_range.min] = IPPROTO_TCP << 16 | res->un.tcp.th_flags;
	#if DEBUG == 1
	struct  servent *service;
	
	printf("%u/tcp return ", ntohs(res->un.tcp.th_sport));
	printf("%s ", port_status[tcp_res[env.current_scan][res->un.tcp.th_flags]]);
	if ((service = getservbyport(res->un.tcp.th_sport, NULL)))
		printf("service %s\n", service->s_name);
	else
		printf("service unknown\n");
	#endif
}

void	response_icmp(struct buffer *res) 
{
	struct buffer *ptr = (void*)&res->un.icmp + sizeof(struct icmphdr);
	if (ptr->ip.protocol == IPPROTO_TCP)
	{
		#if DEBUG == 1
		printf("%u/icmp return ", ntohs(ptr->un.tcp.th_dport));
		printf("%s ", port_status[icmp_res[env.current_scan][res->un.icmp.type][res->un.icmp.code]]);
		struct  servent *service;
		if ((service = getservbyport(res->un.tcp.th_dport, NULL)))
			printf("service %s \n", service->s_name);
		else
			printf("service unknown \n");
		#endif
		if (ntohs(ptr->un.udp.uh_dport) < env.flag.port_range.max && ntohs(ptr->un.udp.uh_dport)\
			> env.flag.port_range.min)
		env.response[env.current_scan][ntohs(ptr->un.tcp.th_dport) - env.flag.port_range.min] =\
			(IPPROTO_ICMP << 16) | (res->un.icmp.type << 8) | (res->un.icmp.code);
	}
	else if (ptr->ip.protocol == IPPROTO_UDP)
	{
		#if DEBUG == 1
		printf("%u/icmp return ", ntohs(ptr->un.udp.uh_dport));
		printf("%s ", port_status[icmp_res[env.current_scan][res->un.icmp.type][res->un.icmp.code]]);
		struct  servent *service;
		if ((service = getservbyport(res->un.udp.uh_dport, NULL)))
			printf("service %s \n", service->s_name);
		else
			printf("service unknown \n");
		#endif
		if (ntohs(ptr->un.udp.uh_dport) < env.flag.port_range.max && ntohs(ptr->un.udp.uh_dport)\
			> env.flag.port_range.min)
			env.response[env.current_scan][ntohs(ptr->un.udp.uh_dport) - env.flag.port_range.min] =\
				(IPPROTO_ICMP << 16) | (res->un.icmp.type << 8) | (res->un.icmp.code);
	}
	else
	{
		#if DEBUG == 1
		printf("Unknown protocol %s %u\n", __FILE__, __LINE__);
		#endif
	}
}

void	response_udp(struct buffer *res) 
{
	env.response[env.current_scan][ntohs(res->un.udp.uh_sport) - env.flag.port_range.min] = (IPPROTO_UDP << 16);
	#if DEBUG == 1
	printf("%u/udp return ", ntohs(res->un.udp.uh_sport));
	printf("%s ", port_status[PORT_OPEN]);
	struct  servent *service;
	if ((service = getservbyport(res->un.udp.uh_sport, NULL)))
		printf("service %s\n", service->s_name);
	else
		printf("service unknown\n");
	#endif
}

void (*res_type[])(struct buffer *res) = {
	[IPPROTO_TCP] = response_tcp,
	[IPPROTO_UDP] = response_udp,
	[IPPROTO_ICMP] = response_icmp,
};

void got_packet(__attribute__((unused))u_char *args, __attribute__((unused))const struct pcap_pkthdr *header, const u_char *packet)
{
	struct packets	*sniff;

	alarm(env.timeout);
	sniff = (struct packets*)packet;
	uint16_t protocol = sniff->buf.ip.protocol;
	#if DEBUG == 1
	struct in_addr src;
	struct in_addr dst;
	struct hostent *p;

	dst.s_addr = sniff->buf.ip.daddr;
	src.s_addr = sniff->buf.ip.saddr;
	if ((p = gethostbyaddr(&sniff->buf.ip.saddr, 8, AF_INET)))
		printf(GREEN_TEXT("SRC %s "), p->h_name);
	else
		printf(GREEN_TEXT("SRC %s "), inet_ntoa(src));
	if ((p = gethostbyaddr(&sniff->buf.ip.daddr, 8, AF_INET)))
		printf(BLUE_TEXT("DST %s \n"), p->h_name);
	else
		printf(BLUE_TEXT("DST %s \n"), inet_ntoa(dst));
	#endif
	if (protocol < sizeof(res_type) && sniff->buf.ip.id != env.pid && res_type[protocol])
		res_type[protocol](&sniff->buf);
}
