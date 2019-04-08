/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jjourdai <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/12/17 18:12:39 by jjourdai          #+#    #+#             */
/*   Updated: 2019/02/01 11:03:40 by jjourdai         ###   ########.fr       */
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
# include <pcap.h>

# define COUNT_OF(ptr) (sizeof(ptr) / sizeof((ptr)[0]))
# define USAGE "ft_nmap [--help] [--ports [NOMBRE/PLAGE]] --ip ADRESSE IP [--speedup [NOMBRE]] [--scan [TYPE]] \n"\
				"ft_nmap [--help] [--ports [NOMBRE/PLAGE]] --file FICHIER [--speedup [NOMBRE]] [--scan [TYPE]]\n"

# define HELPER "--help, -h Print this help screen\n"\
				"--ports, -p ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n"\
				"--ip, -i ip addresses to scan in dot format\n"\
				"--file, -f File name containing IP addresses to scan,\n"\
				"--speedup, -t [250 max] number of parallel threads to use\n"\
				"--scan, -s  SYN/NULL/FIN/XMAS/ACK/UDP\n"\

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

# define DEBUG 1
# define __FATAL(X, ...) handle_error(__LINE__, __FILE__, FATAL, X, __VA_ARGS__)
# define __ASSERTI(ERR_VALUE, RETURN_VALUE, STRING) x_int(ERR_VALUE, RETURN_VALUE, STRING, __FILE__, __LINE__)
# define __ASSERT(ERR_VALUE, RETURN_VALUE, STRING) x_void(ERR_VALUE, RETURN_VALUE, STRING, __FILE__, __LINE__)

enum	options {
	F_HELP = (1 << 0),
	F_PORT = (1 << 1),
	F_SPEED = (1 << 2),
	F_SCANTYPE = (1 << 3),
	F_FILE = 0x30,
	F_IP = 0x10,
};

enum	thread {
	THREAD_MIN = 0,
	THREAD_MAX = 250,
};

enum	scantype {
	_SYN = (1 << 0), 
	_NULL = (1 << 1),
	_ACK = (1 << 2), 
	_FIN = (1 << 3),
	_XMAS = (1 << 4), //TCP REQ with FIN, PSH et URG
	_UDP = (1 << 5), //UDP REQ without data
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
};

//struct pcap_pkthdr {
//		struct timeval ts; /* time stamp */
//		bpf_u_int32 caplen; /* length of portion present */
//		bpf_u_int32 len; /* length this packet (off wire) */	
//};

/*


enum	port_status {
	OPENED,
	CLOSED,
	FILTERED,
	UNFILTERED,
};

*/

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
	} un;
	uint8_t	data[128];
}__attribute__((packed)); 

struct packets {
	struct sniff_ethernet	eth;
	struct buffer		buf;
};


struct nmap {
	struct {
		uint8_t		value;
		uint8_t		thread;
		uint8_t		scantype;
		char		*ip;
		char		**file;
		struct port_range {
			uint16_t	min;
			uint16_t	max;
		} port_range;
	} flag;
	uint32_t	my_ip;
	uint32_t	socket;
	struct addrinfo	*addr;
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

struct thread_job { //data struct to send at pthread_create

};

struct nmap env;

/* params.c */
t_list	*get_params(char **argv, int argc, uint32_t *flag);
void	get_options(int argc, char **argv);

/* init.c */

void		init_iphdr(struct iphdr *ip, uint32_t dest);
void		init_icmphdr(struct icmphdr *hdr);
void		init_tcphdr(struct tcphdr *hdr);
void		init_udp(struct udphdr *hdr);
void		init_env_socket(char *domain);
void		init_receive_buffer(void);

/* error.c */
void	handle_error(uint32_t line, char *file, t_bool fatal, uint32_t error_code,  ...);
int		x_int(int err, int res, char *str, char *file, int line);
void	*x_roid(void *err, void *res, char *str, char *file, int line);

#endif
