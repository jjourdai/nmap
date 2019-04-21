/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   send.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: polooo <polooo@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/21 17:49:48 by polooo            #+#    #+#             */
/*   Updated: 2019/04/21 19:01:05 by polooo           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

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

void	send_udp_packet(uint8_t scan_type, uint16_t port, struct buffer *buf)
{
	struct package test;

	init_udphdr(&buf->un.udp, port);
	ft_bzero(&test, sizeof(test));
	test.psd.ip_source = buf->ip.saddr;
	test.psd.ip_dest = buf->ip.daddr;
	test.psd.mbz = 0;
	test.psd.type = info_scan[scan_type].proto;
	test.psd.length = htons(sizeof(struct buffer) - sizeof(struct iphdr));
	ft_memcpy(&test.un.udp, &buf->un.udp, sizeof(struct buffer) - sizeof(struct iphdr));
	buf->un.udp.check = compute_checksum(&test, sizeof(struct buffer) - sizeof(struct iphdr));
}

void	send_tcp_packet(uint8_t scan_type, uint16_t port, struct buffer *buf)
{
	struct package test;

	init_tcphdr(&buf->un.tcp, port, info_scan[scan_type].flag);
	ft_bzero(&test, sizeof(test));
	test.psd.ip_source = buf->ip.saddr;
	test.psd.ip_dest = buf->ip.daddr;
	test.psd.mbz = 0;
	test.psd.type = info_scan[scan_type].proto;
	test.psd.length = htons(sizeof(struct buffer) - sizeof(struct iphdr));
	ft_memcpy(&test.un.tcp, &buf->un.tcp, sizeof(struct buffer) - sizeof(struct iphdr));
	buf->un.tcp.check = compute_checksum(&test, sizeof(struct buffer) - sizeof(struct iphdr));
}

void	send_packet(uint8_t scan_type, uint16_t port)
{
	struct buffer	buf;
	struct pollfd	poll_list;

	ft_bzero(&buf, sizeof(buf));
	init_iphdr(&buf.ip, ((struct sockaddr_in*)env.addr->ai_addr)->sin_addr.s_addr, info_scan[scan_type].proto);
	buf.ip.saddr = ((struct sockaddr_in *)&env.my_ip)->sin_addr.s_addr;
	if (info_scan[scan_type].proto == IPPROTO_TCP)
		send_tcp_packet(scan_type, port, &buf);
	else if (info_scan[scan_type].proto == IPPROTO_UDP)
		send_udp_packet(scan_type, port, &buf);
	socklen_t addrlen = sizeof(struct sockaddr);
	poll_list.fd = env.socket;
	poll_list.events = POLLOUT;
	__ASSERTI(-1, poll(&poll_list, 1, 0), "poll");
	__ASSERTI(-1, sendto(env.socket, &buf, sizeof(buf), 0, (const struct sockaddr*)env.addr->ai_addr, addrlen), "sendto");
}
