/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   init_2.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: polooo <polooo@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/21 18:47:36 by polooo            #+#    #+#             */
/*   Updated: 2019/04/21 19:00:01 by polooo           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

struct addrinfo *result_dns(char *domain)
{
	struct addrinfo	hints;
	struct addrinfo	*result = NULL;

	ft_bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_CANONNAME;
	if (getaddrinfo(domain, NULL, &hints, &result) != 0)
	{
		__FATAL(UNKNOWN_HOST, BINARY_NAME, domain);
		return (NULL);
	}
	else
		return (result);
}

char		*resolve_device_2(struct sockaddr *src)
{
	struct ifaddrs	*addrs;
	struct ifaddrs	*tmp;
	char			*result;

	getifaddrs(&addrs);
	tmp = addrs;
	while (tmp)
	{
		if (((struct sockaddr_in*)src)->sin_addr.s_addr ==
			((struct sockaddr_in*)tmp->ifa_addr)->sin_addr.s_addr)
		{
			result = ft_strdup(tmp->ifa_name);
			freeifaddrs(addrs);
			return (result);
		}
		tmp = tmp->ifa_next;
	}
	freeifaddrs(addrs);
	return (NULL);
}

char		*resolve_device(struct sockaddr *src)
{
	socklen_t		len;
	int				ret;
	int				sockfd;

	len = sizeof(struct sockaddr);
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	connect(sockfd, src, len);
	ret = getsockname(sockfd, &env.my_ip, &len);
	close(sockfd);
	if (ret)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		return (NULL);
	}
	return (resolve_device_2(&env.my_ip));
}

void		init_pcap(struct pcap_info *pcap)
{
	pcap->device = resolve_device(env.addr->ai_addr);
	#if DEBUG == 1
		printf("device=%s\n", pcap->device);
	#endif
	if (!pcap->device)
	{
		fprintf(stderr, "cannot find interface\n");
		exit(EXIT_FAILURE);
	}
	if ((pcap->session = pcap_open_live(pcap->device, BUFSIZ, 1, 1000, pcap->errbuf)) == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", pcap->device, pcap->errbuf);
		exit(EXIT_FAILURE);
	}
	/* get ipv4 address and netmask of a device */
	if (pcap_lookupnet(pcap->device, &pcap->net, &pcap->netmask, pcap->errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "Can't get netmask for device %s\n", pcap->device);
		exit(EXIT_FAILURE);
	}
	free(pcap->device);
}

int create_socket(void *domain)
{
	int		soc;

	env.addr = result_dns(domain);
	if (((struct sockaddr_in*)env.addr->ai_addr)->sin_addr.s_addr == INADDR_BROADCAST)
	{
		fprintf(stderr, "Do you want to ping broadcast? but No\n");
		exit(EXIT_FAILURE);
	}
	soc = __ASSERTI(-1, socket(PF_INET, SOCK_RAW, IPPROTO_RAW), "socket:");
	//__ASSERTI(-1, setsockopt(soc, IPPROTO_IP, IP_HDRINCL, &opt_value, sizeof(opt_value)), "setsockopt:");
	return (soc);
}
