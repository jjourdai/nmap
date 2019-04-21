/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   result.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: polooo <polooo@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/21 17:37:32 by polooo            #+#    #+#             */
/*   Updated: 2019/04/21 17:46:53 by polooo           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"
#include "colors.h"

#define TREE "|-----------------------------------------"
#define FORMAT "\n%*.*s %-28s %-15s"

const uint8_t icmp_res[][128][128] = {
	[_SYN] = {
		[ICMP_DEST_UNREACH] = {
			[ICMP_HOST_UNREACH] = PORT_FILTERED,
			[ICMP_PROT_UNREACH] = PORT_FILTERED,
			[ICMP_PORT_UNREACH] = PORT_FILTERED,
			[ICMP_NET_ANO] = PORT_FILTERED,
			[ICMP_HOST_ANO] = PORT_FILTERED,
			[ICMP_PKT_FILTERED] = PORT_FILTERED,
		},
	},
	[_NULL] = {
		[ICMP_DEST_UNREACH] = {
			[ICMP_HOST_UNREACH] = PORT_FILTERED,
			[ICMP_PROT_UNREACH] = PORT_FILTERED,
			[ICMP_PORT_UNREACH] = PORT_FILTERED,
			[ICMP_NET_ANO] = PORT_FILTERED,
			[ICMP_HOST_ANO] = PORT_FILTERED,
			[ICMP_PKT_FILTERED] = PORT_FILTERED,
		},
	},
	[_FIN] = {
		[ICMP_DEST_UNREACH] = {
			[ICMP_HOST_UNREACH] = PORT_FILTERED,
			[ICMP_PROT_UNREACH] = PORT_FILTERED,
			[ICMP_PORT_UNREACH] = PORT_FILTERED,
			[ICMP_NET_ANO] = PORT_FILTERED,
			[ICMP_HOST_ANO] = PORT_FILTERED,
			[ICMP_PKT_FILTERED] = PORT_FILTERED,
		},
	},
	[_XMAS] = {
		[ICMP_DEST_UNREACH] = {
			[ICMP_HOST_UNREACH] = PORT_FILTERED,
			[ICMP_PROT_UNREACH] = PORT_FILTERED,
			[ICMP_PORT_UNREACH] = PORT_FILTERED,
			[ICMP_NET_ANO] = PORT_FILTERED,
			[ICMP_HOST_ANO] = PORT_FILTERED,
			[ICMP_PKT_FILTERED] = PORT_FILTERED,
		},
	},
	[_ACK] = {
		[ICMP_DEST_UNREACH] = {
			[ICMP_HOST_UNREACH] = PORT_FILTERED,
			[ICMP_PROT_UNREACH] = PORT_FILTERED,
			[ICMP_PORT_UNREACH] = PORT_FILTERED,
			[ICMP_NET_ANO] = PORT_FILTERED,
			[ICMP_HOST_ANO] = PORT_FILTERED,
			[ICMP_PKT_FILTERED] = PORT_FILTERED,
		},
	},
	[_UDP] = {
		[ICMP_DEST_UNREACH] = {
			[ICMP_HOST_UNREACH] = PORT_FILTERED,
			[ICMP_PROT_UNREACH] = PORT_FILTERED,
			[ICMP_NET_ANO] = PORT_FILTERED,
			[ICMP_HOST_ANO] = PORT_FILTERED,
			[ICMP_PKT_FILTERED] = PORT_FILTERED,
			[ICMP_PORT_UNREACH] = PORT_CLOSED,
		},
	},
};

const uint8_t tcp_res[][128] = {
		[_SYN] = {
			[TH_SYN | TH_ACK] = PORT_OPEN,
			[TH_RST] = PORT_CLOSED,
			[TH_RST | TH_ACK] = PORT_CLOSED,
		},
		[_NULL] = {
			[TH_RST] = PORT_CLOSED,
			[TH_RST | TH_ACK] = PORT_CLOSED,
		},
		[_FIN] = {
			[TH_RST] = PORT_CLOSED,
			[TH_RST | TH_ACK] = PORT_CLOSED,
		},
		[_XMAS] = {
			[TH_RST] = PORT_CLOSED,
			[TH_RST | TH_ACK] = PORT_CLOSED,
		},
		[_ACK] = {
			[TH_RST] = PORT_UNFILTERED,
		},
};

enum e_port_state 	display_tcp(uint8_t scantype, uint16_t value) 
{
	uint8_t status_port = tcp_res[scantype][value];
	uint8_t	flag;

	if (env.flag.value & F_VERBOSE) {
		printf(FORMAT, 32, 15, TREE, scan_type_string[scantype], port_status[status_port]);
		flag = 0x01;
		while (flag <= TH_URG) {
			if (flag & value) {
				printf("%s ", tcp_flag_string[flag]);
			}
			flag = flag << 1;
		}
	}
	return (status_port);
}

enum e_port_state 	display_udp(uint8_t scantype, uint16_t value) 
{
	(void)value;
	if (env.flag.value & F_VERBOSE) {
		printf(FORMAT"udp response", 32, 15, TREE, scan_type_string[scantype], port_status[PORT_OPEN]);
	}
	return (PORT_OPEN);
}

enum e_port_state 	display_icmp(uint8_t scantype, uint16_t value) 
{
	uint8_t status_port = icmp_res[scantype][value >> 8][value & 0xff];

	if (env.flag.value & F_VERBOSE) {
		printf(FORMAT"%s", 32, 15, TREE, scan_type_string[scantype], port_status[status_port], icmp_code_string[value & 0xff]);
	}
	return (status_port);
}
	
enum e_port_state	(*display_by_type[])(uint8_t scantype, uint16_t value) = {
	[IPPROTO_TCP] = display_tcp,
	[IPPROTO_UDP] = display_udp,
	[IPPROTO_ICMP] = display_icmp,
};

void		display_verbosity_result(void)
{
	uint16_t port, range = env.flag.port_range.max - env.flag.port_range.min, real_port;
	uint8_t bit, scan_type;
	struct  servent *service;

	printf(GREEN_TEXT("%-8s") CYAN_TEXT("%-25s") RED_TEXT("%-29s") RED_TEXT("%-15s") RED_TEXT("%s\n"),  "Ports", "Service Name","Scan type", "Results", "Reason"); 
	printf("------------------------------------------------------------------------------------------\n");
	for (port = 0; port < range + 1; port++)
	{
		real_port = port + env.flag.port_range.min;
		bit = 1;
		if ((service = getservbyport(htons(real_port), NULL)))
			printf(GREEN_TEXT("%-10u ")  CYAN_TEXT("%-15s "), real_port, service->s_name);
		else
			printf(GREEN_TEXT("%-10u ") CYAN_TEXT("%-15s "), real_port, "Unassigned");
		while (bit <= 32)
		{
			scan_type = env.flag.scantype & bit;
			if (scan_type != 0)
			{
				if (env.response[scan_type][port] >> 16 == 0)
					printf(FORMAT"%s", 32, 15, TREE, scan_type_string[scan_type], timeout_result[scan_type], "no-response ");
				else if (display_by_type[env.response[scan_type][port] >> 16])
					display_by_type[env.response[scan_type][port] >> 16](scan_type, (uint16_t)env.response[scan_type][port]);
			}
			bit = bit << 1;
		}
		printf("\n");
	}
}

void		display_short_result(void)
{
	uint16_t port, range = env.flag.port_range.max - env.flag.port_range.min, real_port;
	uint8_t bit, scan_type;
	struct  servent *service;
	enum e_port_state status;

	printf(GREEN_TEXT("%-10s") RED_TEXT("%-10s") CYAN_TEXT("%-25s\n"), "Ports", "Results", "Service Name"); 
	printf("----------------------------------------------------------------------------\n");
	for (port = 0; port < range + 1; port++) {
		real_port = port + env.flag.port_range.min;
		bit = 1;
		while (bit <= 32) {
			scan_type = env.flag.scantype & bit;
			if (scan_type != 0 && display_by_type[env.response[scan_type][port] >> 16] && (status =\
						display_by_type[env.response[scan_type][port] >> 16](scan_type,\
							(uint16_t)env.response[scan_type][port])) == PORT_OPEN ) {
				if (scan_type == _UDP)
					printf(GREEN_TEXT("udp/%-6u")  RED_TEXT("%-10s"), real_port, port_status[status]);
				else
					printf(GREEN_TEXT("tcp/%-6u") RED_TEXT("%-10s"), real_port, port_status[status]);
				if ((service = getservbyport(htons(real_port), NULL)))
					printf(CYAN_TEXT("%-25s\n"), service->s_name);
				else
					printf(CYAN_TEXT("%-25s\n"), "Unassigned");
			}
			bit = bit << 1;
		}
	}
}
