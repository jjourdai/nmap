/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jjourdai <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/12 12:28:59 by jjourdai          #+#    #+#             */
/*   Updated: 2018/09/19 14:01:29 by jjourdai         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"
#include "colors.h"

void	longname_opt(char *str)
{
	(void)str;
	fprintf(stderr, "traceroute: function not inplemented\n");
	exit(EXIT_FAILURE);
}

/*
static t_parameters *store_parameters(char *str, enum options flag)
{
	static t_parameters new_param;

	new_param.str = str;
	new_param.code = flag;
	return (&new_param);
}
*/

static void	get_string(char *str, void *ptr)
{
	*((char **)ptr) = str;
}

static void	get_thread(char *str, void *ptr)
{
	uint32_t number = ft_atoi_u(str);

	if (number == THREAD_MIN) {
		__FATAL(THREAD_ZERO, BINARY_NAME, number);
	} else if (number > THREAD_MAX) {
		__FATAL(TOO_MANY_THREAD, BINARY_NAME, number, THREAD_MAX);
	}
	*((uint8_t*)ptr) = number;
}

static void	get_port(char *str, void *ptr)
{
	struct port_range *port;
	char		*hyphen;
	uint32_t	min;
	uint32_t	max;

	port = ptr;
	min = ft_atoi_u(str);
	if ((hyphen = ft_strchr(str, '-'))) {
		if (*(hyphen + 1)) {
			max = ft_atoi_u(hyphen + 1);
			port->min = min;
			port->max = max;
			if (min > max)
				__FATAL(THREAD_MIN_NOT_GREATER, BINARY_NAME);
		} else {
				__FATAL(INVALID_PORT_SYNTAX, BINARY_NAME);
		}
	} else {
		min = ft_atoi_u(str);
		port->min = min;
		port->max = min;
	}
}

static char	*scantype[] = {
	[_SYN] = "SYN",
	[_NULL] = "NULL",
	[_ACK] = "ACK",
	[_FIN] = "FIN",
	[_XMAS] = "XMAS",
	[_UDP] = "UDP",
	[_ALL] = "ALL",
};

static void	get_scantype(char *str, void *ptr)
{
	uint32_t i = -1;

	while (++i < COUNT_OF(scantype))
	{
		if (ft_strcmp(str, scantype[i]) == 0) {
			*((uint8_t*)ptr) = i;
			return ;
		}
	}
	__FATAL(UNKNOWN_TYPE, str);
}

static struct params_getter options[] = {
	{"help", 'h', F_HELP, NULL, NULL},
	{"ports", 'p', F_PORT, get_port, &env.flag.port_range},
	{"speedup", 't', F_SPEED, get_thread, &env.flag.thread},
	{"scan", 's', F_SCANTYPE, get_scantype, &env.flag.scantype},
	{"ip", 'i', F_IP, get_string, &env.flag.ip},
	{"file", 'f', F_FILE, get_string, &env.flag.file},
};

t_list		*get_params(char **argv, int argc, uint8_t *flag)
{
	int 	i, j, flag_has_found;
	uint8_t	index;
	char	c;
	t_list	*parameters;

	i = 0;
	parameters = NULL;
	while (++i < argc)
	{
		if (ft_strncmp(argv[i], "--", 2) == 0) {
				longname_opt(argv[1]);
		}
		else if (argv[i][0] == '-') {
			j = 0;
			while ((c = argv[i][++j]))
			{
				index = -1;
				flag_has_found = 0;
				while (++index < COUNT_OF(options))
				{
					if (options[index].short_name == c) {
						flag_has_found = 1;
						if ((*flag & options[index].code) == options[index].code) {
							fprintf(stderr, GREEN_TEXT("nmap: Warning --%s have been previously stored you could have an undefined  behaviour\n"), options[index].long_name);
						}
						*flag |= options[index].code;
						if (options[index].f != NULL) {
							if (argv[i][j + 1] != '\0') {
									options[index].f(&argv[i][j + 1], options[index].var);
							} else if (argv[i + 1] != NULL) {
									options[index].f(argv[++i], options[index].var);
							} else {
								__FATAL(REQUIRED_ARG, c);
							}
						}
						break ;
					}
				}
				if (flag_has_found != 1) {
					__FATAL(INVALID_OPT, c);
				} else
					break ;
			}
		}
//		else
//				list_push_back(&parameters, store_parameters(argv[i], DOMAIN), sizeof(t_parameters));
	}
	return (parameters);
}

void	get_options(int argc, char **argv)
{
	t_list	*parameters;

	ft_bzero(&env, sizeof(env));
	parameters = get_params(argv, argc, &env.flag.value);
	if (env.flag.value & F_HELP) {
		fprintf(stderr, GREEN_TEXT(USAGE)); exit(EXIT_FAILURE);
	}

/* test print */
	if (env.flag.value & F_PORT)
		ft_putendl("F_PORT");
	if (env.flag.value & F_SPEED)
		ft_putendl("F_SPEED"); printf("%u\n", env.flag.thread);
	if (env.flag.value & F_SCANTYPE)
		ft_putendl("F_SCANTYPE"); ft_putendl(scantype[env.flag.scantype]);
	if ((env.flag.value & F_FILE) == F_FILE)
		ft_putendl("F_FILE"); ft_putendl(env.flag.file);
	if ((env.flag.value & F_IP) == F_IP)
		ft_putendl("F_IP"); ft_putendl(env.flag.ip);
/* end test print */
	list_remove(&parameters, remove_content);
}
