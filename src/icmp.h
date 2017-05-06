/*
 *  WrapSix
 *  Copyright (C) 2008-2017  xHire <xhire@wrapsix.org>
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

#ifndef ICMP_H
#define ICMP_H

#include "ipv4.h"
#include "ipv6.h"

/* ICMP types */
#define ICMPV4_ECHO_REPLY	0x0
#define ICMPV4_ECHO_REQUEST	0x8
#define ICMPV4_DST_UNREACHABLE	0x3
#define ICMPV4_TIME_EXCEEDED	0xb
#define ICMPV4_PARAM_PROBLEM	0xc

/* ICMPv6 types */
#define ICMPV6_DST_UNREACHABLE	0x1
#define ICMPV6_PKT_TOO_BIG	0x2
#define ICMPV6_TIME_EXCEEDED	0x3
#define ICMPV6_PARAM_PROBLEM	0x4
#define ICMPV6_ECHO_REQUEST	0x80
#define ICMPV6_ECHO_REPLY	0x81
#define ICMPV6_NDP_RS		0x85
#define ICMPV6_NDP_RA		0x86
#define ICMPV6_NDP_NS		0x87
#define ICMPV6_NDP_NA		0x88
#define ICMPV6_NDP_RM		0x89

/* ICMP NDP NA Flag (INNAF) */
#define INNAF_R			0x80		/* router flag */
#define INNAF_S			0x40		/* solicited flag */
#define INNAF_O			0x20		/* override flag */

/* ICMP header structure */
struct s_icmp {
	unsigned char		type;           /*  8 b; ICMP type */
	unsigned char		code;           /*  8 b; subtype of ICMP type */
	unsigned short		checksum;       /* 16 b */
} __attribute__ ((__packed__));

/* ICMP echo structure */
struct s_icmp_echo {
	unsigned short		id;		/* 16 b; ID value */
	unsigned short		seq;		/* 16 b; sequence number */
} __attribute__ ((__packed__));

/* ICMP NDP NS structure */
struct s_icmp_ndp_ns {
	unsigned int		zeros;		/*  32 b; reserved section */
	struct s_ipv6_addr	target;		/* 128 b; target IP address */
} __attribute__ ((__packed__));

/* ICMP NDP NA structure */
struct s_icmp_ndp_na {
	unsigned char		flags;		/*   8 b; 3 flags */
	unsigned int		zeros:24;	/*  24 b; reserved section */
	struct s_ipv6_addr	target;		/* 128 b; target IP address */
	unsigned char		opt_type;	/*   8 b; option -- type */
	unsigned char		opt_len;	/*   8 b; option -- length */
	struct s_mac_addr	opt_tlla;	/*  48 b; option -- target
							  link-layer address */
} __attribute__ ((__packed__));

int icmp_ipv4(struct s_ethernet *eth, struct s_ipv4 *ip4, char *payload,
	      unsigned short payload_size);
int icmp_ipv6(struct s_ethernet *eth, struct s_ipv6 *ip6, char *payload);
int icmp_ndp(struct s_ethernet *ethq, struct s_ipv6 *ipq,
	     struct s_icmp_ndp_ns *ndp_ns);

int icmp4_error(struct s_ipv4_addr ip_dest, unsigned char type,
		unsigned char code, char *data, unsigned short length);
int icmp6_error(struct s_mac_addr mac_dest, struct s_ipv6_addr ip_dest,
		unsigned char type, unsigned char code, char *data,
		unsigned short length);

#endif /* ICMP_H */
