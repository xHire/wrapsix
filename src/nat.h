/*
 *  WrapSix
 *  Copyright (C) 2008-2012  xHire <xhire@wrapsix.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NAT_H
#define NAT_H

#include "ethernet.h"		/* s_mac_addr */
#include "ipv4.h"		/* s_ipv4_addr */
#include "ipv6.h"		/* s_ipv6_addr */
#include "linkedlist.h"		/* linkedlist_h */
#include "radixtree.h"		/* radixtree_t */

struct s_nat {
	struct s_mac_addr	mac;
	struct s_ipv6_addr	ipv6;
	struct s_ipv4_addr	ipv4;
	unsigned short		ipv6_port_src;
	unsigned short		ipv4_port_src;
	unsigned short		ipv4_port_dst;
	unsigned char		state;
	linkedlist_node_t	*llnode;
};

struct s_nat_fragments {
	unsigned short	 id;
	struct s_nat	*connection;
	linkedlist_t	*queue;
};

extern radixtree_t *nat6_tcp, *nat6_udp, *nat6_icmp,
		   *nat4_tcp, *nat4_udp, *nat4_icmp,
		   *nat4_tcp_fragments;

extern linkedlist_t *timeout_icmp, *timeout_udp,
		    *timeout_tcp_est, *timeout_tcp_trans,
		    *timeout_tcp_fragments;

void nat_init(void);
void nat_quit(void);

struct s_nat *nat_out(radixtree_t *nat_proto6, radixtree_t *nat_proto4,
		      struct s_mac_addr eth_src,
		      struct s_ipv6_addr ipv6_src, struct s_ipv6_addr ipv6_dst,
		      unsigned short	 port_src, unsigned short     port_dst,
		      unsigned char create);
struct s_nat *nat_in(radixtree_t *nat_proto4, struct s_ipv4_addr ipv4_src,
		     unsigned short port_src, unsigned short port_dst);
struct s_nat_fragments *nat_in_fragments(radixtree_t *nat,
					 linkedlist_t *nat_timeout,
					 struct s_ipv4_addr ipv4_src,
					 unsigned short id);
void nat_in_fragments_cleanup(radixtree_t *nat_proto4,
			      struct s_ipv4_addr ipv4_src, unsigned short id);
void nat_cleaning(void);

#endif /* NAT_H */
