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
# include <arpa/inet.h>
# include <sys/select.h>
# include <sys/time.h>
# include <netdb.h>
# include <stdarg.h>
# include <fcntl.h>

# define COUNT_OF(ptr) (sizeof(ptr) / sizeof((ptr)[0]))
# define USAGE "ft_nmap [--help] [--ports [NOMBRE/PLAGE]] --ip ADRESSE IP [--speedup [NOMBRE]] [--scan [TYPE]] \nft_nmap [--help] [--ports [NOMBRE/PLAGE]] --file FICHIER [--speedup [NOMBRE]] [--scan [TYPE]]\n"

# define TRUE 1
# define FALSE 0
# define FATAL TRUE
# define IP_LEN 15
# define FILENAME_LEN 255
# define DNS_LEN FILENAME_LEN
# define BINARY_NAME "ft_nmap"
# define DUP_ON 1
# define DUP_OFF 0

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
	_XMAS = (1 << 4), 
	_UDP = (1 << 5),
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

struct nmap env;

/* params.c */
t_list	*get_params(char **argv, int argc, uint32_t *flag);
void	get_options(int argc, char **argv);

/* init.c */

void		init_iphdr(struct ip *ip, struct in_addr *dest);
void		init_icmphdr(struct icmphdr *icmp);
void		init_env_socket(char *domain);
void		init_receive_buffer(void);

/* error.c */
void	handle_error(uint32_t line, char *file, t_bool fatal, uint32_t error_code,  ...);
int		x_int(int err, int res, char *str, char *file, int line);
void	*x_roid(void *err, void *res, char *str, char *file, int line);

#endif
