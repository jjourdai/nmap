#include "nmap.h"
#include "colors.h"

void	is_root(void)
{
	if (getuid() == 0)
		return ;
	fprintf(stderr, "You must be logged as root\n");
	exit(EXIT_FAILURE);
}

//struct pcap_pkthdr {
//		struct timeval ts; /* time stamp */
//		bpf_u_int32 caplen; /* length of portion present */
//		bpf_u_int32 len; /* length this packet (off wire) */
//};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct packets *sniff;

	sniff = (struct packets*)packet;
	printf("SRC %s DEST %s\n", inet_ntoa(*((struct in_addr*)&sniff->buf.ip.saddr)), inet_ntoa(*((struct in_addr*)&sniff->buf.ip.daddr)));
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

void	send_packet(void)
{
	struct buffer buf;
	ft_bzero(&buf, sizeof(buf));
	init_iphdr(&buf.ip, ((struct sockaddr_in*)env.addr->ai_addr)->sin_addr.s_addr);
	buf.ip.saddr = env.my_ip;
	init_tcphdr(&buf.un.tcp);
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

int	main(int argc, char **argv)
{
	pthread_t thread1;
	
	get_options(argc, argv);
	env.socket = create_socket(env.flag.ip);
	
	char 				*device, errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32			 netmask;
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
	
	__ASSERTI(-1, pthread_create(&thread1, NULL, send_packet, NULL), "pthread_create");
	/* Search default device */

	struct bpf_program	fp;		/* The compiled filter expression */
	char 			filter_exp[] = "port 256";	/* The filter expression */

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
