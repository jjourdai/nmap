#include "nmap.h"
#include "colors.h"

void	is_root(void)
{
	if (getuid() == 0)
		return ;
	fprintf(stderr, "You must be logged as root\n");
	exit(EXIT_FAILURE);
}

uint64_t	handle_timer(const struct timeval *now, const struct timeval *past)
{
	uint64_t time = ((now->tv_sec) << 20) | (now->tv_usec);
	uint64_t time2 = ((past->tv_sec) << 20) | (past->tv_usec);
	return time - time2;
}

const char *scan_type_string[] = {
	[_SYN] = "SYN",
	[_ACK] = "ACK",
	[_NULL] = "NULL",
	[_XMAS] = "XMAS",
	[_FIN] = "FIN",
	[_UDP] = "UDP",
};

const char *timeout_result[] = {
	[_SYN] = "Filtered",
	[_ACK] = "Filtered",
	[_NULL] = "Open|Filtered",
	[_FIN] = "Open|Filtered",
	[_XMAS] = "Open|Filtered",
	[_UDP] = "Open|Filtered",
};

const char *tcp_flag_string[] = {
	[TH_FIN] = "fin",
	[TH_SYN] = "syn",
	[TH_RST] = "rst",
	[TH_PUSH] = "push",
	[TH_ACK] = "ack",
	[TH_URG] = "urg",
};

const char *icmp_type_string[] = {
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

const char *icmp_code_string[] = {
	[ICMP_HOST_UNREACH] = "Host unreach",
	[ICMP_PROT_UNREACH] = "Prot unreach",
	[ICMP_PORT_UNREACH] = "Port unreach",
	[ICMP_NET_ANO] = "Net ano",	  
	[ICMP_HOST_ANO] = "Host ano",	  
	[ICMP_PKT_FILTERED] = "Pkt filtered",
}; 

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
	[0] = "Undefined",
};

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

void		update_filter(struct pcap_info *pcap)
{
	struct bpf_program	fp;		/* The compiled filter expression */
	char 				filter_exp[256];	/* The filter expression */

	sprintf(filter_exp, "src host %s and (dst port %u or icmp)", env.flag.ip, env.flag.port_src);
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
	if (pcap_loop(pcap->session, 0, got_packet, NULL))
	{
	}
}

void		signal_handler(int signal)
{
	if (signal == SIGALRM)
	{
		write(1, ".", 1);
		pcap_breakloop(env.pcap.session);
	}
}

void		init_sigaction(void)
{
	struct sigaction sig = {
		.sa_handler = signal_handler,
	};
	sigaction(SIGALRM, &sig, NULL);
}

void		nmap_loop(void)
{
	struct timeval	initial_time, now;
	struct hostent	*p;	

	env.socket = create_socket(env.flag.ip);
	init_pcap(&env.pcap);
	ft_bzero(&env.response, sizeof(env.response));
	update_filter(&env.pcap);
	gettimeofday(&initial_time, NULL);
	if ((p = gethostbyaddr(&((struct sockaddr_in*)env.addr->ai_addr)->sin_addr.s_addr, 8, AF_INET))) {
		printf("Permform scan on %s DNS record %s\n", env.flag.ip, p->h_name);
	} else {
		printf("Permform scan on %s\n", env.flag.ip);
	}
	uint8_t bit = 1;
	while (bit <= 32)
	{
		if ((env.flag.scantype & bit) != 0)
		{
			env.current_scan = env.flag.scantype & bit;
			pthread_cond_broadcast(&env.cond);
			alarm(env.timeout);
			listen_packets(&env.pcap);
		}
		bit = bit << 1;
	}
	gettimeofday(&now, NULL);
	printf("\nScan on %s took : %.5f secs\n", env.flag.ip, (double)handle_timer(&now, &initial_time) / 1000000);
	freeaddrinfo(env.addr);
	if (env.flag.value & F_VERBOSE)
		display_verbosity_result();
	else
		display_short_result();
	pcap_close(env.pcap.session);
	close(env.socket);
}

int		main(int argc, char **argv)
{
	get_options(argc, argv);
	init_sigaction();
	env.pid = getpid();
	env.timeout = 1;
	env.cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;
	create_thread_pool();
	if (env.flag.ip)
		nmap_loop();
	else
	{
		uint64_t i = -1;
		while (env.flag.file[++i])
		{
			env.flag.ip = env.flag.file[i];
			nmap_loop();
			free(env.flag.file[i]);
		}
		free(env.flag.file);
	}
	remove_thread_pool();
	return (EXIT_SUCCESS);
}
