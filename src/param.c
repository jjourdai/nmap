/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   param.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: polooo <polooo@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/12 12:28:59 by jjourdai          #+#    #+#             */
/*   Updated: 2019/04/13 18:44:42 by polooo           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"
#include "colors.h"

static void	get_ip_in_file(char *str, void *ptr)
{
	int		file;
	int		ret;
	char	*line;
	char	**ips;
	int		ips_found;
	t_list	*list = NULL;

	ips = *((char***)ptr);
	file = __ASSERTI(-1, open(str, O_RDONLY), "open");	
	while ((ret = get_next_line(file, &line)))
	{
		if (ret == -1) 
			break;
		list_push(&list, &line, sizeof(char*));
	}
	free(line);
	ips_found = list_size(list);
	ips = ft_memalloc((ips_found + 1) * sizeof(char *));
	if (ips_found == 0)
		__FATAL(FILE_IS_EMPTY, BINARY_NAME, str);
	int i;
	char **free_ptr;
	for (i = 0; i < ips_found; i++)
	{
		free_ptr = ((char**)list_pop_front(&list));
		ips[i] = *free_ptr;
		free(free_ptr);
	}
	*((char***)ptr) = ips;
}

static void	get_source_port(char *str, void *ptr)
{
	uint32_t port = ft_atoi_u(str);
	
	if (ft_str_is_only_digit(str) == 0) {
		__FATAL(NOT_ONLY_DIGIT, BINARY_NAME, str);
	} else if (port > 0xFFFF) {
		__FATAL(PORT_NOT_EXIST, BINARY_NAME, str);
	}
	*((uint16_t*)ptr) = port;
}

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
	t_port_range *port;
	char		*hyphen;
	uint32_t	min;
	uint32_t	max;

	port = ptr;
	min = ft_atoi_u(str);
	if ((hyphen = ft_strchr_base(str, "-:"))) {
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
	if (port->max - port->min > RANGE_MAX) {
		__FATAL(RANGE_MAX_EXCEEDED, BINARY_NAME, port->max - port->min, RANGE_MAX);
	}
}

struct scan_type type[] = {
	{_SYN, "SYN"},
	{_NULL, "NULL"},
	{_ACK, "ACK"},
	{_FIN, "FIN"},
	{_XMAS, "XMAS"},
	{_UDP, "UDP"},
};

static void	get_scantype(char *str, void *ptr)
{
	uint32_t i = -1;

	while (++i < COUNT_OF(type))
	{
		if (ft_strcmp(str, type[i].str) == 0) {
			//		printf("%llx\n", *((uint8_t*)ptr));
			*((uint8_t*)ptr) ^= type[i].flag;
			//		printf("%llx\n", *((uint8_t*)ptr));
			return ;
		}
	}
	__FATAL(UNKNOWN_TYPE, BINARY_NAME, str);
}

static struct params_getter options[] = {
	{"help", 'h', F_HELP, NULL, NULL, DUP_OFF},
	{"ports", 'p', F_PORT, get_port, &env.flag.port_range, DUP_OFF},
	{"speedup", 't', F_SPEED, get_thread, &env.flag.thread, DUP_OFF},
	{"scan", 's', F_SCANTYPE, get_scantype, &env.flag.scantype, DUP_ON},
	{"ip", 'i', F_IP, get_string, &env.flag.ip, DUP_OFF},
	{"file", 'f', F_FILE, get_ip_in_file, &env.flag.file, DUP_OFF},
	{"verbose", 'v', F_VERBOSE, NULL, NULL, DUP_OFF},
	{"source_port", 'e', F_SRC_PORT, get_source_port, &env.flag.port_src, DUP_OFF},
};

void	longname_opt(char **argv, uint32_t *flag, int *i)
{
	uint8_t index;
	char	*string;

	string = argv[*i] + 2;
	index = -1;
	while (++index < COUNT_OF(options))
	{
		if (ft_strcmp(options[index].long_name, string) == 0) {
			if ((*flag & options[index].code) == options[index].code && options[index].dup == DUP_OFF) {
				fprintf(stderr, GREEN_TEXT("nmap: Warning --%s have been previously stored you could have an undefined behaviour\n"), options[index].long_name);
			}
			*flag |= options[index].code;
			if (options[index].f != NULL) {
				if (argv[*i + 1] != NULL) {
					return options[index].f(argv[++(*i)], options[index].var);
				} else {
					__FATAL(REQUIRED_ARG, BINARY_NAME, options[index].long_name);
				}
			} else {
				return ;
			}
		}
	}
	__FATAL(INVALID_OPT, BINARY_NAME, string);
}

void	shortname_opt(char **argv, uint32_t *flag, int *i)
{
	int		j, flag_has_found;
	uint8_t index;
	char	c;

	j = 0;
	while ((c = argv[*i][++j]))
	{
		index = -1;
		flag_has_found = 0;
		while (++index < COUNT_OF(options))
		{
			if (options[index].short_name == c) {
				flag_has_found = 1;
				if ((*flag & options[index].code) == options[index].code && options[index].dup == DUP_OFF) {
					fprintf(stderr, GREEN_TEXT("nmap: Warning --%s have been previously stored you could have an undefined behaviour\n"), options[index].long_name);
				}
				*flag |= options[index].code;
				if (options[index].f != NULL) {
					if (argv[*i][j + 1] != '\0') {
						return options[index].f(&argv[*i][++j], options[index].var);
					} else if (argv[*i + 1] != NULL) {
						return options[index].f(argv[++(*i)], options[index].var);
					} else {
						__FATAL(REQUIRED_ARG, BINARY_NAME, options[index].long_name);
					}
				}
			}
		}
		if (flag_has_found != 1) {
			__FATAL(INVALID_SHORT_OPT, BINARY_NAME, c);
		}
	}
}

t_list		*get_params(char **argv, int argc, uint32_t *flag)
{
	int 	i;
	t_list	*parameters;

	i = 0;
	parameters = NULL;
	while (++i < argc)
	{
		if (ft_strncmp(argv[i], "--", 2) == 0) {
			longname_opt(argv, flag, &i);
		} else if (argv[i][0] == '-') {
			shortname_opt(argv, flag, &i);	
		} else {
			__FATAL(UNDEFINED_PARAMETER, BINARY_NAME, argv[i]);
		}
		//		else
		//				list_push_back(&parameters, store_parameters(argv[i], DOMAIN), sizeof(t_parameters));
	}
	return (parameters);
}

void	print_scan_configuration(void)
{
	uint32_t	i;
	
	printf(BLUE_TEXT("Scan Configurations:\n"));
	if (env.flag.file != NULL) {
		printf(BLUE_TEXT("File Input detected:\n"));
		for (i = 0; env.flag.file[i]; i++) {
			printf(BLUE_TEXT("Target IP address: %s\n"), env.flag.file[i]);
		}
	} else {
		printf(BLUE_TEXT("Target IP address: %s\n"), env.flag.ip);
	}
	if (env.flag.port_range.min != env.flag.port_range.max)
		printf(BLUE_TEXT("Port range: %u-%u\n"), env.flag.port_range.min, env.flag.port_range.max);
	else
		printf(BLUE_TEXT("Port to scan: %u\n"), env.flag.port_range.min);
	if (env.flag.scantype == _ALL) {
		printf(BLUE_TEXT("Scans to be performed:  %10s\n"), "ALL");
	} else {
		uint8_t i;
		printf(BLUE_TEXT("Scans to be performed: "));
		for (i = 0; i < COUNT_OF(type); i++)
		{
			if (env.flag.scantype & type[i].flag) {
				printf(BLUE_TEXT("    %s,"), type[i].str);
			}
		}
		printf("\n");
	}
	printf(BLUE_TEXT("Thread Number: %u\n"), env.flag.thread);
}

void	get_options(int argc, char **argv)
{
	/* default parameters */
	ft_bzero(&env, sizeof(env));
	env.flag.scantype = _ALL;
	env.flag.thread = 1;
	env.flag.port_range.min = 1;	
	env.flag.port_range.max = RANGE_MAX;
	env.flag.port_src = SOURCE_PORT;
	/**********************/
	get_params(argv, argc, (uint32_t*)&env.flag.value);
	if (env.flag.value & F_HELP) {
		fprintf(stderr, GREEN_TEXT(USAGE) GREEN_TEXT(HELPER)); exit(EXIT_FAILURE);
	}
	if (env.flag.ip == NULL && env.flag.file == NULL) {
		__FATAL(NO_DEST_GIVEN, BINARY_NAME);
	} else if (env.flag.ip != NULL && env.flag.file != NULL) {
		__FATAL(IP_AND_FILE_GIVEN, BINARY_NAME);
	}
	if (env.flag.scantype != _ALL) {
		env.flag.scantype = ~(env.flag.scantype & _ALL);
	}
	print_scan_configuration();
	env.flag.scantype = (env.flag.scantype & _ALL);
	//	list_remove(&parameters, remove_content);
}
