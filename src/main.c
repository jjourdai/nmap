#include "nmap.h"
#include "colors.h"

void	is_root(void)
{
	if (getuid() == 0)
		return ;
	fprintf(stderr, "You must be logged as root\n");
	exit(EXIT_FAILURE);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct packets *sniff;

	sniff = (struct packets*)packet;
	printf("SRC %s DEST %s SRC_PORT %u DST_PORT %u\n", inet_ntoa(*((struct in_addr*)&sniff->buf.ip.saddr)), inet_ntoa(*((struct in_addr*)&sniff->buf.ip.daddr)), ntohs(sniff->buf.un.tcp.th_sport), ntohs(sniff->buf.un.tcp.th_dport));
	//printf("Sniffed packet_len [%u]\n", header->len);
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
	printf("%d\n", pthread_self());
	sleep(1);
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
	
void	send_packet(uint8_t scan_type, uint16_t port)
{
	struct buffer buf;
	ft_bzero(&buf, sizeof(buf));
	init_iphdr(&buf.ip, ((struct sockaddr_in*)env.addr->ai_addr)->sin_addr.s_addr, IPPROTO_TCP);
	buf.ip.saddr = env.my_ip;
	init_tcphdr(&buf.un.tcp, port, scan_type);
	struct package test;

	ft_bzero(&test, sizeof(test));
	test.psd.ip_source = buf.ip.saddr;
	test.psd.ip_dest = buf.ip.daddr;
	test.psd.mbz = 0;
	test.psd.type = IPPROTO_TCP; // | IPPROTO_UDP;
	test.psd.length = htons(sizeof(struct buffer) - sizeof(struct iphdr));
	ft_memcpy(&test.un.tcp, &buf.un.tcp, sizeof(struct buffer) - sizeof(struct iphdr));
	buf.un.tcp.check = compute_checksum(&test, sizeof(struct buffer) - sizeof(struct iphdr));
	socklen_t addrlen = sizeof(struct sockaddr);
	__ASSERTI(-1, sendto(env.socket, &buf, sizeof(buf), 0, (const struct sockaddr*)env.addr->ai_addr, addrlen), "sendto");
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

static int scantype_value[] = {
	[_SYN] = TH_SYN,
	[_NULL] = 0,
	[_ACK] = TH_ACK,
	[_FIN] = TH_FIN,
	[_XMAS] = TH_FIN | TH_PUSH | TH_URG,
//	[_UDP] = ,
};

void	run_thread(t_thread_task *task)
{
	uint16_t	port;
	uint32_t	scantype = scantype_value[task->scan_type];

	printf("hello, I'm a thread running on [%hu-%hu] :D\n", task->port_range.min, task->port_range.max);
	port = task->port_range.min - 1;
	while (++port < task->port_range.max)
	{
		send_packet(scantype, port);
	}
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
	
	char 				*device, errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32			netmask;
	pcap_t				*session;

	if ((device = pcap_lookupdev(errbuf)) == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf); exit(EXIT_FAILURE);
	}
	printf("Device: %s\n", device);
	/* Open the default device */
	if ((session = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf)) == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf); exit(EXIT_FAILURE);
	}
	/* get ipv4 address and netmask of a device */
	if (pcap_lookupnet(device, &env.my_ip, &netmask, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "Can't get netmask for device %s\n", device); exit(EXIT_FAILURE);
	}

	i = (size_t)-1;
	while (++i < env.flag.thread)
	{
		env.threads[i].port_range.min = env.flag.port_range.min + ((i * (env.flag.port_range.max - env.flag.port_range.min + 1)) / env.flag.thread);
		env.threads[i].port_range.max = env.flag.port_range.min + (((i + 1) * (env.flag.port_range.max - env.flag.port_range.min + 1)) / env.flag.thread) - 1;
		env.threads[i].ports = &env.ports[env.threads[i].port_range.min - env.flag.port_range.min];
		if (!(ret = pthread_create(&env.threads[i].id, NULL, (void *)&run_thread, &env.threads[i])))
			;
	}
//	i = (size_t)-1;
//	while (++i < env.flag.thread)
//		pthread_join(env.threads[i].id, NULL);

	struct bpf_program	fp;		/* The compiled filter expression */
	char 			filter_exp[] = "dst google.com";/* The filter expression */

	if (pcap_compile(session, &fp, filter_exp, 0, env.my_ip) == PCAP_ERROR) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(session)); exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(session, &fp) == PCAP_ERROR) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(session)); exit(EXIT_FAILURE);
	}

	const u_char 		*packet;
	struct pcap_pkthdr	header;

	if (pcap_loop(session, 0, got_packet, NULL)) {
	//	if (pcap_dispatch(session, 0, got_packet, NULL)) {
		ft_putendl("pcap_loop has been broken");
	}
	pcap_close(session);
	return (EXIT_SUCCESS);
}
