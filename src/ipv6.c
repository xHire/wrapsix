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
#include "ipv6.h"
#include "log.h"
#include "tcp.h"
#include "udp.h"
#include "wrapper.h"

/**
 * Processing of IPv6 packets.
 *
 * @param	eth	Ethernet header
 * @param	packet	Packet data
 *
 * @return	0 for success
 * @return	1 for failure
 */
int ipv6(struct s_ethernet *eth, char *packet)
{
	struct s_ipv6	*ip;
	char		*payload;

	/* load data into structures */
	ip = (struct s_ipv6 *) packet;
	payload = packet + sizeof(struct s_ipv6);

	/* test if this packet belongs to us */
	if (memcmp(&wrapsix_ipv6_prefix, &ip->ip_dest, 12) != 0 &&
	    memcmp(&ndp_multicast_addr,  &ip->ip_dest, 13) != 0) {
		return 1;
	}

	/* check and decrease hop limit */
	if (ip->hop_limit <= 1) {
		/* deny this error for error ICMP messages */
		if (ip->next_header != IPPROTO_ICMPV6 || payload[0] & 0x80) {
			/* code 0 = hl exceeded in transmit */
			icmp6_error(eth->src, ip->ip_src, ICMPV6_TIME_EXCEEDED,
				    0, packet,
				    htons(ip->len) + sizeof(struct s_ipv6));
		}
		return 1;
	} else {
		ip->hop_limit--;
	}

	switch (ip->next_header) {
		case IPPROTO_TCP:
			log_debug("IPv6 Protocol: TCP");
			return tcp_ipv6(eth, ip, payload);
		case IPPROTO_UDP:
			log_debug("IPv6 Protocol: UDP");
			return udp_ipv6(eth, ip, payload);
		case IPPROTO_ICMPV6:
			log_debug("IPv6 Protocol: ICMP");
			return icmp_ipv6(eth, ip, payload);
		default:
			log_debug("IPv6 Protocol: unknown [%d/0x%x]",
				  ip->next_header, ip->next_header);
			return 1;
	}
}
