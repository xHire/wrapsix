/*
 *  WrapSix
 *  Copyright (C) 2008-2013  xHire <xhire@wrapsix.org>
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

#ifndef IPV6_H
#define IPV6_H

#include "ethernet.h"		/* s_ethernet */

#define IPV6_FLAG_MORE_FRAGMENTS	0x0001

/* IPv6 address structure */
struct s_ipv6_addr {
	unsigned char		addr[16];
} __attribute__ ((__packed__));

/* IPv6 header structure */
struct s_ipv6 {
	unsigned char		ver;		/*   4 b; version */
	unsigned char		traffic_class;	/*   8 b; traffic class */
	unsigned short		flow_label;	/*  20 b; flow label (QOS) */
	unsigned short		len;		/*  16 b; payload length */
	unsigned char		next_header;	/*   8 b; next header */
	unsigned char		hop_limit;	/*   8 b; hop limit (aka TTL) */
	struct s_ipv6_addr	ip_src;		/* 128 b; source address */
	struct s_ipv6_addr	ip_dest;	/* 128 b; destination address */
} __attribute__ ((__packed__));

/* IPv6 fragment header structure */
struct s_ipv6_fragment {
	unsigned char		next_header;	/*  8 b; next header */
	unsigned char		zeros;		/*  8 b; reserved */
	unsigned short		offset_flag;	/* 13 b; fragment offset in B,
						    2 b; reserved,
						    1 b; flag */
	unsigned int		id;		/* 32 b; id of the packet
							 (for fragmentation) */
} __attribute__ ((__packed__));

/* IPv6 pseudoheader structure for checksum */
struct s_ipv6_pseudo {
	struct s_ipv6_addr	ip_src;		/* 128 b; source address */
	struct s_ipv6_addr	ip_dest;	/* 128 b; destination address */
	unsigned int		len;		/*  32 b; payload length */
	unsigned int		zeros:24;	/*  24 b; reserved */
	unsigned char		next_header;	/*   8 b; next header */
} __attribute__ ((__packed__));

/* IPv6 pseudoheader structure for checksum update */
struct s_ipv6_pseudo_delta {
	struct s_ipv6_addr	ip_src;		/* 128 b; source address */
	struct s_ipv6_addr	ip_dest;	/* 128 b; destination address */
	unsigned short		port;		/*  16 b; transport layer
							  address */
} __attribute__ ((__packed__));

int ipv6(struct s_ethernet *eth, char *packet);

#endif /* IPV6_H */
