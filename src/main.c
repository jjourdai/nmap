#include "nmap.h"
#include "colors.h"

void	is_root(void)
{
	if (getuid() == 0)
		return ;
	fprintf(stderr, "You must be logged as root\n");
	exit(EXIT_FAILURE);
}

static char *tcp_flag_string[] = {
	[TH_FIN] = "FIN",
	[TH_SYN] = "SYN",
	[TH_RST] = "RST",
	[TH_PUSH] = "PUSH",
	[TH_ACK] = "ACK",
	[TH_URG] = "URG",
};

static char *icmp_type_string[] = {
	[ICMP_ECHOREPLY] = "ICMP_ECHOREPLY",	     /* Echo Reply			*/
	[ICMP_DEST_UNREACH] = "ICMP_DEST_UNREACH",     /* Destination Unreachable	*/
	[ICMP_SOURCE_QUENCH] = "ICMP_SOURCE_QUENCH",	     /* Source Quench		*/
	[ICMP_REDIRECT]	= "ICMP_REDIRECT",	     /* Redirect (change route)	*/
	[ICMP_ECHO] = "ICMP_ECHO",   /* Echo Request			*/
	[ICMP_TIME_EXCEEDED] = "ICMP_TIME_EXCEEDED",   /* Time Exceeded		*/
	[ICMP_PARAMETERPROB] = "ICMP_PARAMETERPROB",	     /* Parameter Problem		*/
	[ICMP_TIMESTAMP] = "ICMP_TIMESTAMP",	     /* Timestamp Request		*/
	[ICMP_TIMESTAMPREPLY] = "ICMP_TIMESTAMPREPLY",   /* Timestamp Reply		*/
	[ICMP_INFO_REQUEST] = "ICMP_INFO_REQUEST",   /* Information Request		*/
	[ICMP_INFO_REPLY] = "ICMP_INFO_REPLY",    /* Information Reply		*/
	[ICMP_ADDRESS] = "ICMP_ADDRESS",	     /* Address Mask Request		*/
	[ICMP_ADDRESSREPLY] = "ICMP_ADDRESSREPLY",	     /* Address Mask Reply		*/
}
;
/* Codes for UNREACH. */
#define ICMP_NET_UNREACH	0	/* Network Unreachable		*/
#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED		5	/* Source Route failed		*/
#define ICMP_NET_UNKNOWN	6
#define ICMP_HOST_UNKNOWN	7
#define ICMP_HOST_ISOLATED	8
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PREC_VIOLATION	14	/* Precedence violation */
#define ICMP_PREC_CUTOFF	15	/* Precedence cut off */

#define ICMP_HOST_UNREACH	1	/* Host Unreachable		*/
#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH	3	/* Port Unreachable		*/
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_PKT_FILTERED	13	/* Packet filtered */
const uint32_t protocol_ret[] = {
	[IPPROTO_TCP] = OFFSETOF(struct buffer, un.tcp.th_flags),
	[IPPROTO_ICMP] = OFFSETOF(struct buffer, un.icmp) + sizeof(struct icmphdr),
};

const struct scan_type_info info_scan[] = {
	[_SYN] = {IPPROTO_TCP, TH_SYN, },
	[_NULL] = {IPPROTO_TCP, 0, },
	[_FIN] = {IPPROTO_TCP, TH_FIN, },
	[_XMAS] = {IPPROTO_TCP, TH_FIN | TH_PUSH | TH_URG, },
	[_UDP] = {IPPROTO_UDP, 0, },
};

const char *port_status[] = {
	[PORT_OPEN] = "PORT OPEN",
	[PORT_FILTERED] = "PORT FILTERED",
	[PORT_CLOSED] = "PORT CLOSED",
	[PORT_UNFILTERED] = "PORT UNFILTERED",
};

void	response_tcp(struct buffer *res) 
{
	static const uint8_t res_type[][128] = {
		[_SYN] = {
			[TH_SYN | TH_ACK] = PORT_OPEN,
			[TH_RST] = PORT_CLOSED,
		},
		[_NULL] = {
			[TH_RST] = PORT_CLOSED,
		},
		[_FIN] = {
			[TH_RST] = PORT_CLOSED,
		},
		[_XMAS] = {
			[TH_RST] = PORT_CLOSED,
		},
		[_ACK] = {
			[TH_RST] = PORT_UNFILTERED,
		},
	};
	printf("%u/tcp return ", ntohs(res->un.tcp.th_dport));
	printf("%s ", port_status[res_type[env.flag.scantype][res->un.tcp.th_flags]]);
	struct  servent *service;
	if ((service = getservbyport(res->un.tcp.th_sport, NULL))) {
		printf("service %s\n", service->s_name);
	} else {
		printf("service unknown\n");
	}
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
	printf("%u/icmp return ", ntohs(ptr->un.tcp.th_dport));
	printf("%s ", port_status[res_type[env.flag.scantype][res->un.icmp.type][res->un.icmp.code]]);
	struct  servent *service;
	if ((service = getservbyport(res->un.tcp.th_sport, NULL))) {
		printf("service %s \n", service->s_name);
	} else {
		printf("service unknown \n");
	}
}

void	response_udp(struct buffer *res) 
{	
	printf("%u/udp return ", ntohs(res->un.udp.uh_sport));
	printf("%s ", port_status[PORT_OPEN]);
	struct  servent *service;
	if ((service = getservbyport(res->un.tcp.th_sport, NULL))) {
		printf("service %s\n", service->s_name);
	} else {
		printf("service unknown\n");
	}
}

void (*res_type[])(struct buffer *res) = {
	[IPPROTO_TCP] = response_tcp,
	[IPPROTO_UDP] = response_udp,
	[IPPROTO_ICMP] = response_icmp,
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct packets *sniff;
	struct in_addr src;
	struct in_addr dst;

	sniff = (struct packets*)packet;
	dst.s_addr = sniff->buf.ip.daddr;
	src.s_addr = sniff->buf.ip.saddr;
	
	struct hostent *p;	
	if (src.s_addr == env.my_ip) //host + env.flag.ip ne suffit pas a filtre suffisament pareil avec tcpdump
		return ;	
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
	uint16_t protocol = sniff->buf.ip.protocol;
	if (protocol < sizeof(res_type))
		res_type[protocol](&sniff->buf);
/*
	if (protocol == IPPROTO_TCP) {
		printf("tcp/ ");
		uint8_t flag = sniff->buf.un.tcp.th_flags;
		uint8_t bit = 1;
		uint8_t flag_test;
		while (bit <= 32) {
			flag_test = flag & bit;
			if (flag_test != 0)
				printf(RED_TEXT("flag rcv %s\n"), tcp_flag_string[flag_test]);
			bit = bit << 1;
		}
		struct  servent *service;
		if ((service = getservbyport(sniff->buf.un.tcp.th_sport, NULL))) {
			printf(YELLOW_TEXT("service %s "), service->s_name);
		} else {
			printf(YELLOW_TEXT("service unknown "));
		}
		printf(MAGENTA_TEXT("SRC_PORT %u DST_PORT %u\n"), ntohs(sniff->buf.un.tcp.th_sport), ntohs(sniff->buf.un.tcp.th_dport));
	} else {
		if (protocol == IPPROTO_ICMP) {
			printf("icmp/ \n");
			printf("code = %s\n", icmp_type_string[sniff->buf.un.icmp.code]);
			struct buffer *ptr;
			ptr = (void*)&sniff->buf.un.icmp + sizeof(struct icmphdr);
			printf("protocol %u\n", ptr->ip.protocol);
			if (ptr->ip.protocol == IPPROTO_TCP) {
				printf("flags %u\n", ptr->un.tcp.th_flags);
				printf("dest port %u\n", ntohs(ptr->un.tcp.th_sport));
			}
			else if (ptr->ip.protocol == IPPROTO_UDP) {
				printf("dest port %u\n", ntohs(ptr->un.udp.uh_sport));
			}
		}
		else if (protocol == IPPROTO_UDP)
			printf("udp/ \n");
		else
			printf("Unknown protocol/ \n");
	}
*/
	printf("======================================\n");
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

/*
	pcap_lookupdev,  // search default device
	pcap_open_live
	pcap_lookupnet, 
	pcap_geterr, 
	pcap_setfilter
	pcap_compile,
	pcap_close,
	pcap_breakloop, 
	pcap_dispatch
*/

void	run_thread(t_thread_task *task)
{
	uint16_t	port;

	printf("hello, I'm a thread running on [%hu-%hu] :D\n", task->port_range.min, task->port_range.max);
	port = task->port_range.min - 1;
	while (port < task->port_range.max)
	{
		send_packet(task->scan_type, ++port);
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

void		init_pcap(struct pcap_info *pcap)
{
	if ((pcap->device = pcap_lookupdev(pcap->errbuf)) == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", pcap->errbuf); exit(EXIT_FAILURE);
	}
	printf("Device: %s\n", pcap->device);
	/* Open the default device */
	if ((pcap->session = pcap_open_live(pcap->device, BUFSIZ, 1, 1000, pcap->errbuf)) == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", pcap->device, pcap->errbuf); exit(EXIT_FAILURE);
	}
	/* get ipv4 address and netmask of a device */
	if (pcap_lookupnet(pcap->device, &pcap->net, &pcap->netmask, pcap->errbuf) == PCAP_ERROR) {
		fprintf(stderr, "Can't get netmask for device %s\n", pcap->device); exit(EXIT_FAILURE);
	}
	env.my_ip = get_my_ip(pcap->device);
}

void		listen_packets(struct pcap_info *pcap)
{
	struct bpf_program	fp;		/* The compiled filter expression */
	char 			filter_exp[256];/* The filter expression */
	const u_char 		*packet;
	struct pcap_pkthdr	header;

	sprintf(filter_exp, "host %s", env.flag.ip); 
	if (pcap_compile(pcap->session, &fp, filter_exp, 0, pcap->net) == PCAP_ERROR) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap->session)); exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(pcap->session, &fp) == PCAP_ERROR) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap->session)); exit(EXIT_FAILURE);
	}
	if (pcap_loop(pcap->session, 0, got_packet, NULL)) {
	//	if (pcap_dispatch(session, 0, got_packet, NULL)) {
		ft_putendl("pcap_loop has been broken");
	}
	pcap_close(pcap->session);
}

int		main(int argc, char **argv)
{
	int		ret;
	size_t	i;

	is_root();
	pthread_t thread1;
	
	get_options(argc, argv);
	env.pid = getpid();
	env.socket = create_socket(env.flag.ip);
	
	struct pcap_info pcap;

	init_pcap(&pcap);
	i = (size_t)-1;
	while (++i < env.flag.thread)
	{
		env.threads[i].scan_type = env.flag.scantype;
		env.threads[i].port_range.min = env.flag.port_range.min + ((i * (env.flag.port_range.max - env.flag.port_range.min + 1)) / env.flag.thread);
		env.threads[i].port_range.max = env.flag.port_range.min + (((i + 1) * (env.flag.port_range.max - env.flag.port_range.min + 1)) / env.flag.thread) - 1;
		env.threads[i].ports = &env.ports[env.threads[i].port_range.min - env.flag.port_range.min];
		if (!(ret = pthread_create(&env.threads[i].id, NULL, (void *)&run_thread, &env.threads[i]))) {
		}
	}
	listen_packets(&pcap);
//	i = (size_t)-1;
//	while (++i < env.flag.thread)
//		pthread_join(env.threads[i].id, NULL);
	return (EXIT_SUCCESS);
}


