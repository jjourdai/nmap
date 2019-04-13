#include "nmap.h"
#include "colors.h"

static char *flag_string[] = {
	[TH_FIN] = "FIN",
	[TH_SYN] = "SYN",
	[TH_RST] = "RST",
	[TH_PUSH] = "PUSH",
	[TH_ACK] = "ACK",
	[TH_URG] = "URG",
};

void	ft_memdump(void *ptr, size_t size)
{
	size_t	i;

	if (!ptr)
		return ;
	i = 0;
	while (i < size)
	{
		if (!((i + 1) % 4))
			printf("%.2hhx\n", ((uint8_t *)ptr)[i]);
		else
			printf("%.2hhx ", ((uint8_t *)ptr)[i]);
		i++;
	}
	if (i % 4)
		printf("\n");
}

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
	if (protocol == IPPROTO_TCP) {
		uint8_t flag = sniff->buf.un.tcp.th_flags;
		uint8_t bit = 1;
		uint8_t flag_test;
		while (bit <= 32) {
			flag_test = flag & bit;
			if (flag_test != 0)
				printf(RED_TEXT("flag rcv %s\n"), flag_string[flag_test]);
			bit = bit << 1;
		}
		printf("tcp/ ");
		struct  servent *service;
		if (service = getservbyport(sniff->buf.un.tcp.th_sport, NULL)) {
			printf(YELLOW_TEXT("service %s "), service->s_name);
		} else {
			printf(YELLOW_TEXT("service unknown "));
		}
		printf(MAGENTA_TEXT("SRC_PORT %u DST_PORT %u\n"), ntohs(sniff->buf.un.tcp.th_sport), ntohs(sniff->buf.un.tcp.th_dport));
	} else {
		if (protocol == IPPROTO_ICMP) 
			printf("icmp/ \n");

		else if (protocol == IPPROTO_UDP)
			printf("udp/ \n");
		else
			printf("Unknown protocol/ \n");
	}
	ft_memdump(&sniff->buf, sizeof(struct buffer));
	printf("======================================\n");
}

int		main(int argc, char **argv)
{
	char 				*device;
	char				 errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32			my_ip;
	bpf_u_int32			netmask;
	pcap_t				*session;
	struct bpf_program	fp;		/* The compiled filter expression */
	char 				filter_exp[256];/* The filter expression */

	if (argc != 2)
	{
		fprintf(stderr, "print_raw <ip>\n");
		exit(1);
	}

	if ((device = pcap_lookupdev(errbuf)) == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(1);
	}
	printf("Device: %s\n", device);
	/* Open the default device */
	if ((session = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
		exit(1);
	}
	/* get ipv4 address and netmask of a device */
	if (pcap_lookupnet(device, &my_ip, &netmask, errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "Can't get netmask for device %s\n", device);
		exit(1);
	}

	sprintf(filter_exp, "host %s", argv[1]); 
	if (pcap_compile(session, &fp, filter_exp, 0, netmask) == PCAP_ERROR) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(session)); exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(session, &fp) == PCAP_ERROR) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(session)); exit(EXIT_FAILURE);
	}
	if (pcap_loop(session, 0, got_packet, NULL)) {
	//	if (pcap_dispatch(session, 0, got_packet, NULL)) {
		ft_putendl("pcap_loop has been broken");
	}
	pcap_close(session);
	return (0);
}
