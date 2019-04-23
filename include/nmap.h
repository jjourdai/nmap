/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: polooo <polooo@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/12/17 18:12:39 by jjourdai          #+#    #+#             */
/*   Updated: 2019/04/21 19:00:19 by polooo           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef NMAP_H
# define NMAP_H

# include "libft.h"
# include <errno.h>
# include <stdlib.h>
# include <stdio.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <netinet/in.h>
# include <netinet/ip_icmp.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <arpa/inet.h>
# include <sys/select.h>
# include <sys/time.h>
# include <netdb.h>
# include <stdarg.h>
# include <fcntl.h>
# include <pthread.h>
# include <pcap.h>
# include <ifaddrs.h>
# include <sys/ioctl.h>
# include <net/if.h>
# include <signal.h>
# include <poll.h>

# define COUNT_OF(ptr) (sizeof(ptr) / sizeof((ptr)[0]))
# define OFFSETOF(TYPE, MEMBER) ((size_t)&((TYPE *)0)->MEMBER)
# define USAGE "ft_nmap [--help] [--ports [NOMBRE/PLAGE]] --ip ADRESSE IP [--speedup [NOMBRE]] [--scan [TYPE]] \n"\
				"ft_nmap [--help] [--ports [NOMBRE/PLAGE]] --file FICHIER [--speedup [NOMBRE]] [--scan [TYPE]]\n"

# define HELPER "--help, -h Print this help screen\n"\
				"--ports, -p ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n"\
				"--ip, -i ip addresses to scan in dot format\n"\
				"--file, -f File name containing IP addresses to scan,\n"\
				"--speedup, -t [250 max] number of parallel threads to use\n"\
				"--scan, -s  SYN/NULL/FIN/XMAS/ACK/UDP\n"\
				"--verbose, -v Display result\n"\
				"--source_port, -e Choose source port\n"\

# define TRUE 1
# define FALSE 0
# define FATAL TRUE
# define IP_LEN 15
# define FILENAME_LEN 255
# define DNS_LEN FILENAME_LEN
# define BINARY_NAME "ft_nmap"
# define DUP_ON 1
# define DUP_OFF 0
# define RANGE_MAX 1024
# define SOURCE_PORT 48752
# define RETRY_MAX 3
# define DEBUG 1

# define __FATAL(X, ...) handle_error(__LINE__, __FILE__, FATAL, X, __VA_ARGS__)
# define __ASSERTI(ERR_VALUE, RETURN_VALUE, STRING) x_int(ERR_VALUE, RETURN_VALUE, STRING, __FILE__, __LINE__)
# define __ASSERT(ERR_VALUE, RETURN_VALUE, STRING) x_void(ERR_VALUE, RETURN_VALUE, STRING, __FILE__, __LINE__)

# define BIT(n)			(1 << n)
# define SET(x, n)		(x | n)
# define UNSET(x, n)	(x & (~n))
# define ISSET(x, n)	(x & n)

enum	options {
	F_HELP = (1 << 0),
	F_PORT = (1 << 1),
	F_SPEED = (1 << 2),
	F_SCANTYPE = (1 << 3),
	F_VERBOSE = (1 << 4),
	F_IP = (1 << 5),
	F_FILE = (1 << 6),
	F_SRC_PORT = (1 << 6),
};

enum	thread {
	THREAD_MIN = 0,
	THREAD_MAX = 250,
};

enum	scantype {
	_SYN = BIT(0),
	_NULL = BIT(1),
	_ACK = BIT(2),
	_FIN = BIT(3),
	_XMAS = BIT(4),
	_UDP = BIT(5),
	_ALL = 0x3f, //value of all other flag 00111111
};

enum	error {
	THREAD_ZERO,
	TOO_MANY_THREAD,
	THREAD_MIN_NOT_GREATER,
	INVALID_PORT_SYNTAX,
	UNKNOWN_TYPE,
	REQUIRED_ARG,
	INVALID_OPT,
	INVALID_SHORT_OPT,
	UNDEFINED_PARAMETER,
	NO_DEST_GIVEN,
	RANGE_MAX_EXCEEDED,
	IP_AND_FILE_GIVEN,
	NOT_IP_FOUND,
	NOT_ONLY_DIGIT,
	PORT_NOT_EXIST,
	UNKNOWN_HOST,
};

enum	e_port_state
{
	TIMEOUT = 0,
	PORT_OPEN = BIT(0),
	PORT_FILTERED = BIT(1),
	PORT_CLOSED = BIT(2),
	PORT_UNFILTERED = BIT(3),
	TIMEOUT2 = 10,
};

struct scan_type_info {
	uint16_t proto;
	uint16_t flag;
};

struct pcap_info {
	pcap_t		*session;
	bpf_u_int32	netmask;
	bpf_u_int32	net;
	char		errbuf[PCAP_ERRBUF_SIZE];
	char		*device;
};

typedef struct	s_port_range
{
	uint16_t	min;
	uint16_t	max;
}				t_port_range;

typedef struct	s_port
{
	uint16_t	number;
	uint16_t	state;
}				t_port;

typedef struct	s_thread_task
{
	pthread_t			id;
	pthread_mutex_t		mutex;
	t_port_range		port_range;
	int					run;
}		t_thread_task;

#define ETHER_ADDR_LEN	6
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

struct buffer {
	struct iphdr 			ip;
	union {
		struct tcphdr		tcp;
		struct udphdr		udp;
		struct icmphdr		icmp;
	} un;
	uint8_t	data[20];
}__attribute__((packed)); 

struct packets {
	struct sniff_ethernet	eth;
	struct buffer		buf;
};

struct nmap {
	struct {
		uint8_t			value;
		uint8_t			thread;
		uint8_t			scantype;
		char			*ip;
		char			**file;
		uint16_t		port_src;
		t_port_range	port_range;
	} flag;
	t_thread_task	threads[THREAD_MAX];
	struct sockaddr	my_ip;
	uint8_t		current_scan;
	uint32_t	pid;
	uint32_t	socket;
	uint32_t	timeout;
	uint32_t			response[_UDP + 1][RANGE_MAX];
	struct addrinfo		*addr;
	struct pcap_info	pcap;
	pthread_cond_t		cond;
};

typedef struct parameters {
	char *str;
	enum options code;
}			t_parameters;

struct params_getter {
	char			*long_name;
	char			short_name;
	enum options	code;
	void	(*f)(char *, void *ptr);	
	void			*var;
	uint8_t			dup;
};

struct scan_type {
	uint8_t flag;
	char	*str;
};

struct nmap env;

void	send_packet(uint8_t scan_type, uint16_t port);
void	got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void	display_verbosity_result(void);
void	display_short_result(void);

void	create_thread_pool(void);
void	remove_thread_pool(void);
void	run_thread(t_thread_task *task);

int	create_socket(void *domain);
void	init_pcap(struct pcap_info *pcap);

/* params.c */
t_list	*get_params(char **argv, int argc, uint32_t *flag);
void	get_options(int argc, char **argv);

/* init.c */

void		init_iphdr(struct iphdr *ip, uint32_t dest, uint32_t protocol);
void		init_icmphdr(struct icmphdr *hdr);
void		init_tcphdr(struct tcphdr *hdr, uint32_t port, uint32_t flag_type);
void		init_udphdr(struct udphdr *hdr, uint16_t port);
void		init_env_socket(char *domain);
void		init_receive_buffer(void);

/* error.c */
void	handle_error(uint32_t line, char *file, t_bool fatal, uint32_t error_code,  ...);
int		x_int(int err, int res, char *str, char *file, int line);
void	*x_roid(void *err, void *res, char *str, char *file, int line);

extern const char					*scan_type_string[];
extern const char					*port_status[];
extern const char					*tcp_flag_string[];
extern const char					*icmp_code_string[];
extern const char					*timeout_result[];
extern const struct scan_type_info	info_scan[];
extern const uint8_t				icmp_res[][128][128];
extern const uint8_t				tcp_res[][128];

#endif
