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

#ifndef ETHERNET_H
#define ETHERNET_H

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6	0x86dd
#endif /* ETHERTYPE_IPV6 */

/* MAC address structure */
struct s_mac_addr {
	unsigned char		addr[6];
} __attribute__ ((__packed__));

/* Ethernet header structure */
struct s_ethernet {
	struct s_mac_addr	dest;	/* 48 b; destination host (MAC)
						 address */
	struct s_mac_addr	src;	/* 48 b; source host (MAC) address */
	unsigned short		type;	/* 16 b; IP/ARP/RARP/... */
} __attribute__ ((__packed__));

#endif /* ETHERNET_H */
