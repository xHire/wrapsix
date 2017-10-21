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

#include <netinet/in.h>		/* IPPROTO_* */
#include <string.h>		/* memcmp */

#include "icmp.h"
#include "ipv4.h"
#include "log.h"
#include "tcp.h"
#include "udp.h"
#include "wrapper.h"

/**
 * Processing of IPv4 packets.
 *
 * @param	eth	Ethernet header
 * @param	packet	Packet data
 * @param	length	Packet data length
 *
 * @return	0 for success
 * @return	1 for failure
 */
int ipv4(struct s_ethernet *eth, char *packet, unsigned short length)
{
	struct s_ipv4	*ip;
	char		*payload;
	unsigned short	 header_size;

	/* load IP header */
	ip = (struct s_ipv4 *) packet;

	/* test if this packet belongs to us */
	if (memcmp(&wrapsix_ipv4_addr, &ip->ip_dest, 4) != 0) {
		return 1;
	}

	/* compute sizes and get payload */
	header_size = (ip->ver_hdrlen & 0x0f) * 4;	/* # of 4-byte words */

	/* sanity check */
	if (header_size > length || ntohs(ip->len) != length) {
		log_debug("IPv4 packet of an inconsistent length [dropped]");
		return 1;
	}

	payload = packet + header_size;

	/* check and decrease TTL */
	if (ip->ttl <= 1) {
		/* deny this error for ICMP (except ping/pong)
		 * and for non-first fragments */
		if ((ip->proto != IPPROTO_ICMP ||
		     payload[0] == ICMPV4_ECHO_REPLY ||
		     payload[0] == ICMPV4_ECHO_REQUEST) &&
		    !(ip->flags_offset & htons(0x1fff))) {
			/* code 0 = TTL exceeded in transmit */
			icmp4_error(ip->ip_src, ICMPV4_TIME_EXCEEDED, 0,
				    packet, length);
		}
		return 1;
	} else {
		ip->ttl--;
	}

	#define data_size	length - header_size
	switch (ip->proto) {
		case IPPROTO_TCP:
			log_debug("IPv4 Protocol: TCP");
			return tcp_ipv4(eth, ip, payload, data_size);
		case IPPROTO_UDP:
			log_debug("IPv4 Protocol: UDP");
			return udp_ipv4(eth, ip, payload, data_size);
		case IPPROTO_ICMP:
			log_debug("IPv4 Protocol: ICMP");
			return icmp_ipv4(eth, ip, payload, data_size);
		default:
			log_debug("IPv4 Protocol: unknown [%d/0x%x]",
				  ip->proto, ip->proto);
			return 1;
	}
	#undef data_size
}
