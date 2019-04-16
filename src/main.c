#include "nmap.h"
#include "colors.h"

void	is_root(void)
{
	if (getuid() == 0)
		return ;
	fprintf(stderr, "You must be logged as root\n");
	exit(EXIT_FAILURE);
}

struct response_data res_info[_UDP + 1] = {0};

void	init_response_data_struct(void)
{
	ft_bzero(&res_info, sizeof(res_info));
}

uint64_t	handle_timer(const struct timeval *now, const struct timeval *past)
{
	uint64_t time = ((now->tv_sec) << 20) | (now->tv_usec);
	uint64_t time2 = ((past->tv_sec) << 20) | (past->tv_usec);
	return time - time2;
}

static char *scan_type_string[] = {
	[_SYN] = "SYN",
	[_ACK] = "ACK",
	[_NULL] = "NULL",
	[_XMAS] = "XMAS",
	[_FIN] = "FIN",
	[_UDP] = "UDP",
};

/*
static char *timeout_result[] = {
	[_SYN] = "Filtered",
	[_ACK] = "Filtered",
	[_NULL] = "Open|Filtered",
	[_FIN] = "Open|Filtered",
	[_XMAS] = "Open|Filtered",
	[_UDP] = "Open|Filtered",
};
*/

/*
static char *tcp_flag_string[] = {
	[TH_FIN] = "FIN",
	[TH_SYN] = "SYN",
	[TH_RST] = "RST",
	[TH_PUSH] = "PUSH",
	[TH_ACK] = "ACK",
	[TH_URG] = "URG",
};
*/
/*
static char *icmp_type_string[] = {
	[ICMP_ECHOREPLY] = "ICMP_ECHOREPLY",	     
	[ICMP_DEST_UNREACH] = "ICMP_DEST_UNREACH",   
	[ICMP_SOURCE_QUENCH] = "ICMP_SOURCE_QUENCH", 
	[ICMP_REDIRECT]	= "ICMP_REDIRECT",	     
	[ICMP_ECHO] = "ICMP_ECHO",  
	[ICMP_TIME_EXCEEDED] = "ICMP_TIME_EXCEEDED", 
	[ICMP_PARAMETERPROB] = "ICMP_PARAMETERPROB", 
	[ICMP_TIMESTAMP] = "ICMP_TIMESTAMP",	     
	[ICMP_TIMESTAMPREPLY] = "ICMP_TIMESTAMPREPLY",
	[ICMP_INFO_REQUEST] = "ICMP_INFO_REQUEST",   
	[ICMP_INFO_REPLY] = "ICMP_INFO_REPLY",    
	[ICMP_ADDRESS] = "ICMP_ADDRESS",	     
	[ICMP_ADDRESSREPLY] = "ICMP_ADDRESSREPLY",   
};
*/

const struct scan_type_info info_scan[] = {
	[_SYN] = {IPPROTO_TCP, TH_SYN, },
	[_NULL] = {IPPROTO_TCP, 0, },
	[_FIN] = {IPPROTO_TCP, TH_FIN, },
	[_XMAS] = {IPPROTO_TCP, TH_FIN | TH_PUSH | TH_URG, },
	[_UDP] = {IPPROTO_UDP, 0, },
};

const char *port_status[] = {
	[PORT_OPEN] = "Open",
	[PORT_FILTERED] = "Filtered",
	[PORT_CLOSED] = "Closed",
	[PORT_UNFILTERED] = "Unfiltered",
};

void	response_tcp(struct buffer *res) 
{
	static const uint8_t res_type[][128] = {
		[_SYN] = {
			[TH_SYN | TH_ACK] = PORT_OPEN,
			[TH_RST] = PORT_CLOSED,
			[TH_RST | TH_ACK] = PORT_CLOSED,
		},
		[_NULL] = {
			[TH_RST] = PORT_CLOSED,
			[TH_RST | TH_ACK] = PORT_CLOSED,
		},
		[_FIN] = {
			[TH_RST] = PORT_CLOSED,
			[TH_RST | TH_ACK] = PORT_CLOSED,
		},
		[_XMAS] = {
			[TH_RST] = PORT_CLOSED,
			[TH_RST | TH_ACK] = PORT_CLOSED,
		},
		[_ACK] = {
			[TH_RST] = PORT_UNFILTERED,
		},
	};
	res_info[env.current_scan].ports[ntohs(res->un.tcp.th_sport) - env.flag.port_range.min] = res_type[env.current_scan][res->un.tcp.th_flags];
	#if DEBUG == 1
	struct  servent *service;
	
	printf("%u/tcp return ", ntohs(res->un.tcp.th_sport));
	printf("%s ", port_status[res_type[env.current_scan][res->un.tcp.th_flags]]);
	if ((service = getservbyport(res->un.tcp.th_sport, NULL))) {
		printf("service %s\n", service->s_name);
	} else {
		printf("service unknown\n");
	}
	#endif
}

void	response_icmp(struct buffer *res) 
{
	static const uint8_t res_type[][128][128] = {
		[_SYN] = {
			[ICMP_DEST_UNREACH] = {
				[ICMP_HOST_UNREACH] = PORT_FILTERED,
				[ICMP_PROT_UNREACH] = PORT_FILTERED,
				[ICMP_PORT_UNREACH] = PORT_FILTERED,
				[ICMP_NET_ANO] = PORT_FILTERED,
				[ICMP_HOST_ANO] = PORT_FILTERED,
				[ICMP_PKT_FILTERED] = PORT_FILTERED,
			},
		},
		[_NULL] = {
			[ICMP_DEST_UNREACH] = {
				[ICMP_HOST_UNREACH] = PORT_FILTERED,
				[ICMP_PROT_UNREACH] = PORT_FILTERED,
				[ICMP_PORT_UNREACH] = PORT_FILTERED,
				[ICMP_NET_ANO] = PORT_FILTERED,
				[ICMP_HOST_ANO] = PORT_FILTERED,
				[ICMP_PKT_FILTERED] = PORT_FILTERED,
			},
		},
		[_FIN] = {
			[ICMP_DEST_UNREACH] = {
				[ICMP_HOST_UNREACH] = PORT_FILTERED,
				[ICMP_PROT_UNREACH] = PORT_FILTERED,
				[ICMP_PORT_UNREACH] = PORT_FILTERED,
				[ICMP_NET_ANO] = PORT_FILTERED,
				[ICMP_HOST_ANO] = PORT_FILTERED,
				[ICMP_PKT_FILTERED] = PORT_FILTERED,
			},
		},
		[_XMAS] = {
			[ICMP_DEST_UNREACH] = {
				[ICMP_HOST_UNREACH] = PORT_FILTERED,
				[ICMP_PROT_UNREACH] = PORT_FILTERED,
				[ICMP_PORT_UNREACH] = PORT_FILTERED,
				[ICMP_NET_ANO] = PORT_FILTERED,
				[ICMP_HOST_ANO] = PORT_FILTERED,
				[ICMP_PKT_FILTERED] = PORT_FILTERED,
			},
		},
		[_ACK] = {
			[ICMP_DEST_UNREACH] = {
				[ICMP_HOST_UNREACH] = PORT_FILTERED,
				[ICMP_PROT_UNREACH] = PORT_FILTERED,
				[ICMP_PORT_UNREACH] = PORT_FILTERED,
				[ICMP_NET_ANO] = PORT_FILTERED,
				[ICMP_HOST_ANO] = PORT_FILTERED,
				[ICMP_PKT_FILTERED] = PORT_FILTERED,
			},
		},
		[_UDP] = {
			[ICMP_DEST_UNREACH] = {
				[ICMP_HOST_UNREACH] = PORT_FILTERED,
				[ICMP_PROT_UNREACH] = PORT_FILTERED,
				[ICMP_NET_ANO] = PORT_FILTERED,
				[ICMP_HOST_ANO] = PORT_FILTERED,
				[ICMP_PKT_FILTERED] = PORT_FILTERED,
				[ICMP_PORT_UNREACH] = PORT_CLOSED,
			},
		},
	};

	struct buffer *ptr = (void*)&res->un.icmp + sizeof(struct icmphdr);
	if (ptr->ip.protocol == IPPROTO_TCP) {
		#if DEBUG == 1
		printf("%u/icmp return ", ntohs(ptr->un.tcp.th_dport));
		printf("%s ", port_status[res_type[env.current_scan][res->un.icmp.type][res->un.icmp.code]]);
		struct  servent *service;
		if ((service = getservbyport(res->un.tcp.th_dport, NULL))) {
			printf("service %s \n", service->s_name);
		} else {
			printf("service unknown \n");
		}
		#endif
		res_info[env.current_scan].ports[ntohs(ptr->un.tcp.th_dport) - env.flag.port_range.min] = res_type[env.current_scan][res->un.icmp.type][res->un.icmp.code];
	} else if (ptr->ip.protocol == IPPROTO_UDP) {
		#if DEBUG == 1
		printf("%u/icmp return ", ntohs(ptr->un.udp.uh_dport));
		printf("%s ", port_status[res_type[env.current_scan][res->un.icmp.type][res->un.icmp.code]]);
		struct  servent *service;
		if ((service = getservbyport(res->un.udp.uh_dport, NULL))) {
			printf("service %s \n", service->s_name);
		} else {
			printf("service unknown \n");
		}
		#endif
		res_info[env.current_scan].ports[ntohs(ptr->un.udp.uh_dport) - env.flag.port_range.min] = res_type[env.current_scan][res->un.icmp.type][res->un.icmp.code];
	} else {
		#if DEBUG == 1
		printf("Unknown protocol %s %u\n", __FILE__, __LINE__);
		#endif
	}
}

void	response_udp(struct buffer *res) 
{
	res_info[env.current_scan].ports[ntohs(res->un.udp.uh_sport) - env.flag.port_range.min] = PORT_OPEN;
	#if DEBUG == 1
	printf("%u/udp return ", ntohs(res->un.udp.uh_sport));
	printf("%s ", port_status[PORT_OPEN]);
	struct  servent *service;
	if ((service = getservbyport(res->un.udp.uh_sport, NULL))) {
		printf("service %s\n", service->s_name);
	} else {
		printf("service unknown\n");
	}
	#endif
}

void (*res_type[])(struct buffer *res) = {
	[IPPROTO_TCP] = response_tcp,
	[IPPROTO_UDP] = response_udp,
	[IPPROTO_ICMP] = response_icmp,
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct packets *sniff;
	sniff = (struct packets*)packet;

	uint16_t protocol = sniff->buf.ip.protocol;
	#if DEBUG == 1
	struct in_addr src;
	struct in_addr dst;
	struct hostent *p;

	dst.s_addr = sniff->buf.ip.daddr;
	src.s_addr = sniff->buf.ip.saddr;
	if ((p = gethostbyaddr(&sniff->buf.ip.saddr, 8, AF_INET))) {
		printf(GREEN_TEXT("SRC %s "), p->h_name);
	} else {
		printf(GREEN_TEXT("SRC %s "), inet_ntoa(src));
	}
	if ((p = gethostbyaddr(&sniff->buf.ip.daddr, 8, AF_INET))) {
		printf(BLUE_TEXT("DST %s \n"), p->h_name);
	} else {
		printf(BLUE_TEXT("DST %s \n"), inet_ntoa(dst));
	}
	#endif
	if (protocol < sizeof(res_type) && sniff->buf.ip.id != env.pid)
		res_type[protocol](&sniff->buf);
}

struct addrinfo *result_dns(char *domain)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;

	ft_bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_CANONNAME;
	if (getaddrinfo(domain, NULL, &hints, &result) != 0) {
		fprintf(stderr, "ping: unknown host %s\n", domain); exit(EXIT_FAILURE);
	} else {
		return (result);
	}
}

struct pseudo_entete
{
	unsigned long ip_source; // Adresse ip source
	unsigned long ip_dest; // Adresse ip destination
	char mbz; // Champs à 0
	char type; // Type de protocole (6->TCP et 17->UDP)
	unsigned short length; // htons( Entete TCP ou UDP + Data )
}__attribute__((packed));

struct package { 
	struct pseudo_entete psd;
	union {
		struct tcphdr tcp;
		struct udphdr udp;
	} un;
	uint8_t		data[128];
}__attribute__((packed));

int create_socket(void *domain)
{
	int		soc;

	env.addr = result_dns(domain);
	if (((struct sockaddr_in*)env.addr->ai_addr)->sin_addr.s_addr == INADDR_BROADCAST) {
		fprintf(stderr, "Do you want to ping broadcast? but No\n"); exit(EXIT_FAILURE);
	}
	int opt_value = 1;
	soc = __ASSERTI(-1, socket(PF_INET, SOCK_RAW, IPPROTO_RAW), "socket:");
	__ASSERTI(-1, setsockopt(soc, IPPROTO_IP, IP_HDRINCL, &opt_value, sizeof(opt_value)), "setsockopt:");
	return (soc);
}

void	send_udp_packet(uint8_t scan_type, uint16_t port, struct buffer buf)
{
	struct package test;

	init_udphdr(&buf.un.udp, port);
	ft_bzero(&test, sizeof(test));
	test.psd.ip_source = buf.ip.saddr;
	test.psd.ip_dest = buf.ip.daddr;
	test.psd.mbz = 0;
	test.psd.type = info_scan[scan_type].proto; //IPPROTO_TCP || IPPROTO_UDP
	test.psd.length = htons(sizeof(struct buffer) - sizeof(struct iphdr));
	ft_memcpy(&test.un.udp, &buf.un.udp, sizeof(struct buffer) - sizeof(struct iphdr));
	buf.un.udp.check = compute_checksum(&test, sizeof(struct buffer) - sizeof(struct iphdr));
	socklen_t addrlen = sizeof(struct sockaddr);
	__ASSERTI(-1, sendto(env.socket, &buf, sizeof(buf), 0, (const struct sockaddr*)env.addr->ai_addr, addrlen), "sendto");
}

void	send_tcp_packet(uint8_t scan_type, uint16_t port, struct buffer buf)
{
	struct package test;

	init_tcphdr(&buf.un.tcp, port, info_scan[scan_type].flag);

	ft_bzero(&test, sizeof(test));
	test.psd.ip_source = buf.ip.saddr;
	test.psd.ip_dest = buf.ip.daddr;
	test.psd.mbz = 0;
	test.psd.type = info_scan[scan_type].proto; //IPPROTO_TCP || IPPROTO_UDP
	test.psd.length = htons(sizeof(struct buffer) - sizeof(struct iphdr));
	ft_memcpy(&test.un.tcp, &buf.un.tcp, sizeof(struct buffer) - sizeof(struct iphdr));
	buf.un.tcp.check = compute_checksum(&test, sizeof(struct buffer) - sizeof(struct iphdr));
	socklen_t addrlen = sizeof(struct sockaddr);
	__ASSERTI(-1, sendto(env.socket, &buf, sizeof(buf), 0, (const struct sockaddr*)env.addr->ai_addr, addrlen), "sendto");
}

void	send_packet(uint8_t scan_type, uint16_t port)
{
	struct buffer buf;
	ft_bzero(&buf, sizeof(buf));
	init_iphdr(&buf.ip, ((struct sockaddr_in*)env.addr->ai_addr)->sin_addr.s_addr, info_scan[scan_type].proto);
	buf.ip.saddr = env.my_ip;
	if (info_scan[scan_type].proto == IPPROTO_TCP) {
		send_tcp_packet(scan_type, port, buf);
	} else if (info_scan[scan_type].proto == IPPROTO_UDP) {
		send_udp_packet(scan_type, port, buf);
	}
}

void	run_thread(t_thread_task *task)
{
	uint16_t	port;

	port = task->port_range.min - 1;
	while (port < task->port_range.max)
	{
		if (res_info[env.current_scan].ports[port - env.flag.port_range.min + 1] == TIMEOUT)
			send_packet(task->scan_type, port + 1);
		++port;
	}
}

uint32_t	get_my_ip(char *device)
{
	struct ifaddrs *ifaddr, *tmp;
	struct sockaddr_in *cast;
	uint32_t	my_ip = 0;

	getifaddrs(&ifaddr);
	tmp = ifaddr;
	while (tmp) {
		if (tmp->ifa_addr->sa_family == PF_INET && ft_strcmp(tmp->ifa_name, device) == 0) {
			cast = (struct sockaddr_in*)tmp->ifa_addr;
			my_ip = cast->sin_addr.s_addr;
		}
		tmp = tmp->ifa_next;
	}
	freeifaddrs(ifaddr);
	if (my_ip == 0)
		__FATAL(NOT_IP_FOUND, BINARY_NAME);
	return (my_ip);
}

void		init_pcap(struct pcap_info *pcap, int def)
{
	if (def == 1)
		pcap->device = "lo";
	else if ((pcap->device = pcap_lookupdev(pcap->errbuf)) == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", pcap->errbuf);
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
	struct bpf_program	fp;		/* The compiled filter expression */
	char 				filter_exp[256];	/* The filter expression */

	env.current = pcap;
//	sprintf(filter_exp, "src host %s and (src portrange %hu-%hu or icmp)", env.flag.ip, env.flag.port_range.min, env.flag.port_range.max);
	sprintf(filter_exp, "src host %s and (dst port %u or icmp)", env.flag.ip, SOURCE_PORT);
	/* Open the default device */
	if (pcap_compile(pcap->session, &fp, filter_exp, 0, pcap->net) == PCAP_ERROR)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap->session));
		exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(pcap->session, &fp) == PCAP_ERROR)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap->session));
		exit(EXIT_FAILURE);
	}
	pcap_freecode(&fp);
}

void		listen_packets(struct pcap_info *pcap)
{
	alarm(env.timeout);
	env.current = pcap;
	if (pcap_loop(pcap->session, 0, got_packet, NULL))
	{
	//	if (pcap_dispatch(session, 0, got_packet, NULL)) {
	}
}

void		signal_handler(int signal)
{
	if (signal == SIGALRM)
	{
		pcap_breakloop(env.current->session);
	}
}

void		init_sigaction(void)
{
	struct sigaction sig = {
		.sa_handler = signal_handler,
	};
	//ne pas oublier de closed les SIGALARM
	sigaction(SIGALRM, &sig, NULL);
}

/*
void		display_result(void)
{
	uint16_t port, range = env.flag.port_range.max - env.flag.port_range.min, real_port;
	uint8_t bit, scan_type;
	char	buffer[2048];
	size_t	len_buffer;
	struct  servent *service;

	printf(GREEN_TEXT("%-8s") CYAN_TEXT("%-20s") RED_TEXT("%-28s\n"), "Ports", "Service Name", "Results"); 
	printf("----------------------------------------------------------------------------\n");
	for (port = 0; port < range + 1; port++) {
		real_port = port + env.flag.port_range.min;
		bit = 1;
		if ((service = getservbyport(htons(real_port), NULL))) {
			printf(GREEN_TEXT("%-10u ")  CYAN_TEXT("%-15s "), real_port, service->s_name);
		} else {
			printf(GREEN_TEXT("%-10u ") CYAN_TEXT("%-15s "), real_port, "Unassigned");
		}
		len_buffer = 0;
		while (bit <= 32) {
			scan_type = env.flag.scantype & bit;
			if (scan_type != 0) {
				if (res_info[scan_type].ports[port] != TIMEOUT) {
					len_buffer += sprintf(buffer + len_buffer, "%s(%s) ", scan_type_string[scan_type], port_status[res_info[scan_type].ports[port]]);
				} else {
					len_buffer += sprintf(buffer + len_buffer, "%s(%s) ", scan_type_string[scan_type], timeout_result[scan_type]);
				}
			}
			bit = bit << 1;
		}
		printf(RED_TEXT("%s\n"), buffer);
	}
}
*/

void		display_result(void)
{
	uint16_t port, range = env.flag.port_range.max - env.flag.port_range.min, real_port;
	uint8_t bit, scan_type;
	struct  servent *service;

	printf(GREEN_TEXT("%-10s") RED_TEXT("%-10s") CYAN_TEXT("%-25s\n"), "Ports", "Results", "Service Name"); 
	printf("----------------------------------------------------------------------------\n");
	for (port = 0; port < range + 1; port++) {
		real_port = port + env.flag.port_range.min;
		bit = 1;
		while (bit <= 32) {
			scan_type = env.flag.scantype & bit;
			if (scan_type != 0) {
				if (res_info[scan_type].ports[port] == PORT_OPEN || res_info[scan_type].ports[port] == PORT_CLOSED) {
					if (scan_type == _UDP) {
						printf(GREEN_TEXT("udp/%-6u")  RED_TEXT("%-10s"), real_port, port_status[res_info[scan_type].ports[port]]);
					} else {
						printf(GREEN_TEXT("tcp/%-6u") RED_TEXT("%-10s"), real_port, port_status[res_info[scan_type].ports[port]]);
					}
					if ((service = getservbyport(htons(real_port), NULL))) {
						printf(CYAN_TEXT("%-25s\n"), service->s_name);
					} else {
						printf(CYAN_TEXT("%-25s\n"), "Unassigned");
					}
				} 
			}
			bit = bit << 1;
		}
	}
}

void		nmap_loop(void)
{
	int		ret;
	size_t		i;
	struct timeval	initial_time;
	struct timeval	now;

	gettimeofday(&initial_time, NULL);
	env.socket = create_socket(env.flag.ip);
	env.timeout = 2;
	init_pcap(&env.pcap, 0);
	init_pcap(&env.pcap_local, 1);
	env.my_ip = get_my_ip(env.pcap.device);
	init_response_data_struct();
	uint8_t	current_try;
	uint8_t bit = 1;
	while (bit <= 32) {
		env.current_scan = env.flag.scantype & bit;
		if (env.current_scan != 0) {
			current_try = 0;
			for (; current_try < RETRY_MAX; current_try++) {
				printf(RED_TEXT("Perform Scan %s try %u\n"), scan_type_string[env.current_scan], current_try);
				i = (size_t)-1;
				while (++i < env.flag.thread)
				{
					env.threads[i].scan_type = env.current_scan;
					env.threads[i].port_range.min = env.flag.port_range.min + ((i * (env.flag.port_range.max - env.flag.port_range.min + 1)) / env.flag.thread);
					env.threads[i].port_range.max = env.flag.port_range.min + (((i + 1) * (env.flag.port_range.max - env.flag.port_range.min + 1)) / env.flag.thread) - 1;
					env.threads[i].ports = &env.ports[env.threads[i].port_range.min - env.flag.port_range.min];
					if (!(ret = pthread_create(&env.threads[i].id, NULL, (void *)&run_thread, &env.threads[i])))
					{
					}
				}
				i = (size_t)-1;
				while (++i < env.flag.thread)
					pthread_join(env.threads[i].id, NULL);
				listen_packets(&env.pcap);
				listen_packets(&env.pcap_local);
			}
		}
		bit = bit << 1;
	}
	freeaddrinfo(env.addr);
	close(env.socket);
	pcap_close(env.pcap.session);
	gettimeofday(&now, NULL);
	printf("Scan on %s took : %.5f nsecs\n", env.flag.ip, (double)handle_timer(&now, &initial_time) / 1000000);
	display_result();
	pcap_close(env.pcap_local.session);

}

int		main(int argc, char **argv)
{
	get_options(argc, argv);
	env.pid = getpid();
	init_sigaction();

	if (env.flag.ip)
		nmap_loop();
	else {
		uint64_t i = -1;
		while (env.flag.file[++i]) {
			env.flag.ip = env.flag.file[i];
			nmap_loop();
			free(env.flag.file[i]);
		}
		free(env.flag.file);
	}
	return (EXIT_SUCCESS);
}
