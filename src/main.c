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

//struct pcap_pkthdr {
//		struct timeval ts; /* time stamp */
//		bpf_u_int32 caplen; /* length of portion present */
//		bpf_u_int32 len; /* length this packet (off wire) */
//};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct packets *sniff;

	sniff = (struct packets*)packet;
	printf("SRC %s DEST %s\n", inet_ntoa(*((struct in_addr*)&sniff->ip.saddr)), inet_ntoa(*((struct in_addr*)&sniff->ip.daddr)));
	//printf("Sniffed packet_len [%u]\n", header->len);
}

int	main(int argc, char **argv)
{
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

	/* Search default device */
	char 				*device, errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32			 netmask, net;
	pcap_t				*session;
	struct bpf_program	fp;		/* The compiled filter expression */

	if ((device = pcap_lookupdev(errbuf)) == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf); exit(EXIT_FAILURE);
	}
	printf("Device: %s\n", device);

	/* Open the default device */
	if ((session = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf)) == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf); exit(EXIT_FAILURE);
	}

	/* get ipv4 address and netmask of a device */
	if (pcap_lookupnet(device, &net, &netmask, errbuf) == PCAP_ERROR) {
			fprintf(stderr, "Can't get netmask for device %s\n", device); exit(EXIT_FAILURE);
	}

	char 				filter_exp[] = "port 22";	/* The filter expression */
	
	if (pcap_compile(session, &fp, filter_exp, 0, net) == PCAP_ERROR) {
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
	
	ft_putendl("dwalkdawjkdjawda");

	pcap_close(session);
	return (EXIT_SUCCESS);
}
