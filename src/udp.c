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

#include <net/ethernet.h>	/* ETHERTYPE_* */
#include <netinet/in.h>		/* htons */
#include <string.h>		/* memcpy */

#include "checksum.h"
#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "linkedlist.h"
#include "log.h"
#include "nat.h"
#include "transmitter.h"
#include "udp.h"
#include "wrapper.h"

/**
 * Processing of incoming UDPv4 packets. Directly sends translated UDPv6
 * packets.
 *
 * @param	eth4		Ethernet header
 * @param	ip4		IPv4 header
 * @param	payload		UDPv4 data
 * @param	payload_size	Size of the data payload
 *
 * @return	0 for success
 * @return	1 for failure
 */
int udp_ipv4(struct s_ethernet *eth4, struct s_ipv4 *ip4, char *payload,
	     unsigned short payload_size)
{
	struct s_udp	*udp;
	struct s_nat	*connection;
	unsigned short	 orig_checksum;
	char		 packet[PACKET_BUFFER];

	struct s_ethernet *eth6;
	struct s_ipv6     *ip6;

	/* parse UDP header */
	udp = (struct s_udp *) payload;

	/* sanity check again; the second one is not strictly needed */
	if (payload_size < sizeof(struct s_udp) ||
	    payload_size != ntohs(udp->len)) {
		log_debug("Too short/malformed UDPv4 packet");
		return 1;
	}

	/* checksum recheck */
	if (udp->checksum != 0x0000) {
		orig_checksum = udp->checksum;
		udp->checksum = 0;
		udp->checksum = checksum_ipv4(ip4->ip_src, ip4->ip_dest,
					      payload_size, IPPROTO_UDP,
					      payload);

		if (udp->checksum != orig_checksum) {
			/* packet is corrupted and shouldn't be processed */
			log_debug("Wrong checksum");
			return 1;
		}
	}

	/* find connection in NAT */
	connection = nat_in(nat4_udp, ip4->ip_src,
			    udp->port_src, udp->port_dest);

	if (connection == NULL) {
		log_debug("Incoming connection wasn't found in NAT");
		return 1;
	}

	linkedlist_move2end(timeout_udp, connection->llnode);

	/* translated packet */
	eth6 = (struct s_ethernet *) packet;
	ip6 = (struct s_ipv6 *) (packet + sizeof(struct s_ethernet));

	/* build ethernet header */
	eth6->dest		= connection->mac;
	eth6->src		= mac;
	eth6->type		= htons(ETHERTYPE_IPV6);

	/* build IPv6 packet */
	ip6->ver		= 0x60 | (ip4->tos >> 4);
	ip6->traffic_class	= ip4->tos << 4;
	ip6->flow_label		= 0x0;
	ip6->len		= htons(payload_size);
	ip6->next_header	= IPPROTO_UDP;
	ip6->hop_limit		= ip4->ttl;
	ipv4_to_ipv6(&ip4->ip_src, &ip6->ip_src);
	ip6->ip_dest		= connection->ipv6;

	/* set incoming source port */
	udp->port_dest = connection->ipv6_port_src;

	/* compute UDP checksum */
	if (udp->checksum) {
		udp->checksum = checksum_ipv6_update(udp->checksum,
						     ip4->ip_src, ip4->ip_dest,
						     connection->ipv4_port_src,
						     ip6->ip_src, ip6->ip_dest,
						     connection->ipv6_port_src);
	} else {
		/* if original checksum was 0x0000, we need to compute it */
		udp->checksum = checksum_ipv6(ip6->ip_src, ip6->ip_dest,
					      payload_size, IPPROTO_UDP,
					      (char *) udp);
	}

	/* copy the payload data (with new checksum) */
	memcpy(packet + sizeof(struct s_ethernet) + sizeof(struct s_ipv6),
	       payload, payload_size);

	/* send translated packet */
	transmit_raw(packet, sizeof(struct s_ethernet) + sizeof(struct s_ipv6) +
		     payload_size);

	return 0;
}

/**
 * Processing of outgoing UDPv6 packets. Directly sends translated UDPv4
 * packets.
 *
 * @param	eth6		Ethernet header
 * @param	ip6		IPv6 header
 * @param	payload		UDPv6 data
 * @param	payload_size	Size of the data payload
 *
 * @return	0 for success
 * @return	1 for failure
 */
int udp_ipv6(struct s_ethernet *eth6, struct s_ipv6 *ip6, char *payload,
	     unsigned short payload_size)
{
	struct s_udp	*udp;
	struct s_nat	*connection;
	unsigned short	 orig_checksum;
	struct s_ipv4	*ip4;
	char		 packet[PACKET_BUFFER];
	unsigned int	 packet_size;

	/* parse UDP header */
	udp = (struct s_udp *) payload;

	/* sanity check again; the second one is not strictly needed */
	if (payload_size < sizeof(struct s_udp) ||
	    payload_size != ntohs(udp->len)) {
		log_debug("Too short/malformed UDPv6 packet");
		return 1;
	}

	/* checksum recheck */
	orig_checksum = udp->checksum;
	udp->checksum = 0;
	udp->checksum = checksum_ipv6(ip6->ip_src, ip6->ip_dest, payload_size,
				      IPPROTO_UDP, payload);

	if (udp->checksum != orig_checksum) {
		/* packet is corrupted and shouldn't be processed */
		log_debug("Wrong checksum");
		return 1;
	}

	/* find connection in NAT */
	connection = nat_out(nat6_udp, nat4_udp, eth6->src,
			     ip6->ip_src, ip6->ip_dest,
			     udp->port_src, udp->port_dest, 1);

	if (connection == NULL) {
		log_warn("Outgoing connection wasn't found/created in NAT!");
		return 1;
	}

	if (connection->llnode == NULL) {
		connection->llnode = linkedlist_append(timeout_udp, connection);
	} else {
		linkedlist_move2end(timeout_udp, connection->llnode);
	}


	/* translated packet */
	ip4 = (struct s_ipv4 *) packet;
	packet_size = sizeof(struct s_ipv4) + payload_size;

	/* build IPv4 packet */
	ip4->ver_hdrlen	  = 0x45;		/* ver 4, header length 20 B */
	ip4->tos	  = ((ip6->ver & 0x0f) << 4) |
			    ((ip6->traffic_class & 0xf0) >> 4);
	ip4->len	  = htons(packet_size);
	ip4->id		  = 0x0;
	ip4->flags_offset = htons(IPV4_FLAG_DONT_FRAGMENT);
	ip4->ttl	  = ip6->hop_limit;
	ip4->proto	  = IPPROTO_UDP;
	ip4->ip_src	  = wrapsix_ipv4_addr;
	ipv6_to_ipv4(&ip6->ip_dest, &ip4->ip_dest);

	/* set outgoing source port */
	udp->port_src = connection->ipv4_port_src;

	/* compute UDP checksum */
	udp->checksum = checksum_ipv4_update(udp->checksum,
					     ip6->ip_src, ip6->ip_dest,
					     connection->ipv6_port_src,
					     ip4->ip_src, ip4->ip_dest,
					     connection->ipv4_port_src);

	/* copy the payload data (with new checksum) */
	memcpy(packet + sizeof(struct s_ipv4), payload, payload_size);

	/* compute IPv4 checksum */
	ip4->checksum = 0x0;
	ip4->checksum = checksum(ip4, sizeof(struct s_ipv4));

	/* send translated packet */
	transmit_ipv4(&ip4->ip_dest, packet, packet_size);

	return 0;
}
