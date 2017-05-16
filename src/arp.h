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

#ifndef ARP_H
#define ARP_H

#include "ipv4.h"
#include "ipv6.h"

/* ARP opcodes */
#define ARP_OP_REQUEST	0x0001
#define ARP_OP_REPLY	0x0002

#define ARP_HDR_ETHER	0x0001

/* ARP structure */
struct s_arp {
	unsigned short		hw;		/* 16 b; hardware type
							 [0x0001] */
	unsigned short		proto;		/* 16 b; protocol type
							 [0x0800] */
	unsigned char		hw_len;		/*  8 b; length of hardware
							 addr in bytes [0x06] */
	unsigned char		proto_len;	/*  8 b; length of protocol
							 addr in bytes [0x04] */
	unsigned short		opcode;		/* 16 b; operation code:
							 [0x0001] or [0x0002] */
	struct s_mac_addr	mac_src;	/* 48 b; sender hardware addr */
	struct s_ipv4_addr	ip_src;		/* 32 b; sender protocol addr */
	struct s_mac_addr	mac_dest;	/* 48 b; target hardware addr */
	struct s_ipv4_addr	ip_dest;	/* 32 b; target protocol addr */
} __attribute__ ((__packed__));

int arp(struct s_ethernet *ethq, char *payload);

#endif /* ARP_H */
