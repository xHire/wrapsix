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
#include <stdlib.h>		/* malloc */
#include <string.h>		/* memcpy */

#include "checksum.h"
#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "linkedlist.h"
#include "log.h"
#include "nat.h"
#include "tcp.h"
#include "transmitter.h"
#include "wrapper.h"

/**
 * Processing of incoming TCPv4 packets. Directly sends translated TCPv6
 * packets.
 *
 * The IPv4 packet, although split into several parts, is expected to be stored
 * in a continuous memory.
 *
 * @param	eth4		Ethernet header
 * @param	ip4		IPv4 header
 * @param	payload		TCPv4 data
 * @param	payload_size	Size of the data payload
 *
 * @return	0 for success
 * @return	1 for failure
 */
int tcp_ipv4(struct s_ethernet *eth4, struct s_ipv4 *ip4, char *payload,
	     unsigned short payload_size)
{
	struct s_tcp	*tcp;
	struct s_nat	*connection;
	unsigned short	 tmp_short;
	char		 packet[PACKET_BUFFER];

	char			*saved_packet;
	struct s_nat_fragments	*frag_conn;
	linkedlist_node_t	*llnode;

	struct s_ethernet	*eth6;
	struct s_ipv6		*ip6;
	struct s_ipv6_fragment	*frag;

	/* full processing of unfragmented packet or the first fragment with
	 * TCP header
	 */
	if ((ip4->flags_offset | htons(IPV4_FLAG_DONT_FRAGMENT)) ==
	    htons(IPV4_FLAG_DONT_FRAGMENT) ||
	    ((ip4->flags_offset & htons(IPV4_FLAG_MORE_FRAGMENTS)) &&
	     (ip4->flags_offset & htons(0x1fff)) == 0x0000)) {
		/* sanity check */
		if (payload_size < sizeof(struct s_tcp)) {
			log_debug("Too short TCPv4 packet");
			return 1;
		}

		/* parse TCP header */
		tcp = (struct s_tcp *) payload;

		/* checksum recheck -- only if the packet is unfragmented */
		if ((ip4->flags_offset | htons(IPV4_FLAG_DONT_FRAGMENT)) ==
		    htons(IPV4_FLAG_DONT_FRAGMENT)) {
			tmp_short = tcp->checksum;
			tcp->checksum = 0;
			tcp->checksum = checksum_ipv4(ip4->ip_src, ip4->ip_dest,
						      payload_size, IPPROTO_TCP,
						      (char *) tcp);

			if (tcp->checksum != tmp_short) {
				/* packet is corrupted and shouldn't be
				 * processed */
				log_debug("Wrong TCPv4 checksum");
				return 1;
			}
		}

		/* find connection in NAT */
		connection = nat_in(nat4_tcp, ip4->ip_src,
				    tcp->port_src, tcp->port_dest);

		if (connection == NULL) {
			log_debug("Incoming TCP connection wasn't found in "
				  "NAT");
			return 1;
		}

		/* TCP state machine */
		switch (connection->state) {
			case TCP_STATE_EST:
				if (tcp->flags & TCP_FLAG_FIN) {
					connection->state = TCP_STATE_FIN4;
					break;
				} else if (tcp->flags & TCP_FLAG_RST) {
					connection->state = TCP_STATE_TRANS;
					linkedlist_move2end(timeout_tcp_trans,
							    connection->llnode);
					break;
				} else {
					linkedlist_move2end(timeout_tcp_est,
							    connection->llnode);
					break;
				}

			case TCP_STATE_INIT:
				if (tcp->flags & TCP_FLAG_SYN) {
					connection->state = TCP_STATE_EST;
					linkedlist_move2end(timeout_tcp_est,
							    connection->llnode);
				}
				break;

			case TCP_STATE_FIN4:
				linkedlist_move2end(timeout_tcp_est,
						    connection->llnode);
				break;

			case TCP_STATE_FIN6:
				if (tcp->flags & TCP_FLAG_FIN) {
					connection->state = TCP_STATE_FIN64;
					linkedlist_move2end(timeout_tcp_trans,
							    connection->llnode);
					break;
				} else {
					linkedlist_move2end(timeout_tcp_est,
							    connection->llnode);
					break;
				}

			case TCP_STATE_FIN64:
				break;

			case TCP_STATE_TRANS:
				if (tcp->flags & TCP_FLAG_RST) {
					break;
				} else {
					connection->state = TCP_STATE_EST;
					linkedlist_move2end(timeout_tcp_est,
							    connection->llnode);
					break;
				}
		}

		/* if it's fragmented, save it to fragments table */
		if (ip4->flags_offset & htons(IPV4_FLAG_MORE_FRAGMENTS)) {
			if ((frag_conn = nat_in_fragments(nat4_tcp_fragments,
			     timeout_tcp_fragments, ip4->ip_src, ip4->id)) ==
			     NULL) {
				return 1;
			}

			/* what is probability that there is already some other
			 * connection? if there is such connection then there is
			 * just a little chance to fix something as normally all
			 * our fragments are already processed at this moment */
			frag_conn->connection = connection;

			/* check if there are any saved fragments */
			if (frag_conn->queue != NULL) {
				log_debug("Processing TCPv4 fragments of %d",
					  ip4->id);
				llnode = frag_conn->queue->first.next;
				while (llnode->next != NULL) {
					llnode = llnode->next;
					/* first is fragment size */
					tcp_ipv4((struct s_ethernet *) (
						  (char *) llnode->prev->data +
						  sizeof(unsigned short)),
						 (struct s_ipv4 *) (
						  (char *) llnode->prev->data +
						  sizeof(unsigned short) +
						  sizeof(struct s_ethernet)),
						 (char *) llnode->prev->data +
						  sizeof(unsigned short) +
						  sizeof(struct s_ethernet) +
						  sizeof(struct s_ipv4),
						 *((unsigned short *)
						   llnode->prev->data));
					free(llnode->prev->data);
					linkedlist_delete(frag_conn->queue,
							  llnode->prev);
				}
			}
		}

		/* translated packet */
		eth6 = (struct s_ethernet *) packet;
		ip6 = (struct s_ipv6 *) (packet + sizeof(struct s_ethernet));

		/* build ethernet header */
		eth6->dest		= connection->mac;
		eth6->src		= mac;
		eth6->type		= htons(ETHERTYPE_IPV6);

		/* build IPv6 header */
		ip6->ver		= 0x60 | (ip4->tos >> 4);
		ip6->traffic_class	= ip4->tos << 4;
		ip6->flow_label		= 0x0;
		ip6->hop_limit		= ip4->ttl;
		ipv4_to_ipv6(&ip4->ip_src, &ip6->ip_src);
		ip6->ip_dest		= connection->ipv6;

		/* set incoming source port */
		tcp->port_dest = connection->ipv6_port_src;

		/* compute TCP checksum */
		tcp->checksum = checksum_ipv6_update(tcp->checksum,
						     ip4->ip_src, ip4->ip_dest,
						     connection->ipv4_port_src,
						     ip6->ip_src, ip6->ip_dest,
						     connection->ipv6_port_src);

		/* fragment it or not? */
		if (payload_size > mtu - sizeof(struct s_ipv6)) {
			/* 1st fragments' payload size must be 8-byte aligned */
			#define FRAGMENT_LEN (((mtu - sizeof(struct s_ipv6) - \
				sizeof(struct s_ipv6_fragment)) / 8) * 8)

			/* fill in missing IPv6 header fields */
			ip6->len	 = htons(FRAGMENT_LEN +
						sizeof(struct s_ipv6_fragment));
			ip6->next_header = IPPROTO_FRAGMENT;

			/* create IPv6 fragment header */
			frag = (struct s_ipv6_fragment *) ((char *) ip6 +
				sizeof(struct s_ipv6));
			frag->next_header = IPPROTO_TCP;
			frag->zeros	  = 0x0;
			frag->offset_flag = htons(IPV6_FLAG_MORE_FRAGMENTS);
			frag->id	  = ip4->id ? htonl(htons(ip4->id)) :
						      (unsigned int) rand();

			/* copy the payload data */
			memcpy((char *) frag + sizeof(struct s_ipv6_fragment),
			       payload, FRAGMENT_LEN);

			/* send translated packet */
			transmit_raw(packet, sizeof(struct s_ethernet) +
					     sizeof(struct s_ipv6) +
					     sizeof(struct s_ipv6_fragment) +
					     FRAGMENT_LEN);

			/* create the second fragment */
			ip6->len = htons(payload_size +
					 sizeof(struct s_ipv6_fragment) -
					 FRAGMENT_LEN);
			frag->offset_flag = htons((FRAGMENT_LEN / 8) << 3);

			/* copy the payload data */
			memcpy((char *) frag + sizeof(struct s_ipv6_fragment),
			       payload + FRAGMENT_LEN,
			       payload_size - FRAGMENT_LEN);

			/* send translated packet */
			transmit_raw(packet, sizeof(struct s_ethernet) +
					     sizeof(struct s_ipv6) +
					     sizeof(struct s_ipv6_fragment) -
					     FRAGMENT_LEN + payload_size);
		} else {
			ip6->len	 = htons(payload_size);
			ip6->next_header = IPPROTO_TCP;

			/* copy the payload data */
			memcpy((char *) ip6 + sizeof(struct s_ipv6),
			       payload, payload_size);

			/* send translated packet */
			transmit_raw(packet, sizeof(struct s_ethernet) +
				     sizeof(struct s_ipv6) + payload_size);
		}
	} else {
		/* find connection in fragments table */
		if ((frag_conn = nat_in_fragments(nat4_tcp_fragments,
		     timeout_tcp_fragments, ip4->ip_src, ip4->id)) == NULL) {
			return 1;
		}

		if (frag_conn->connection == NULL) {
			log_debug("Incoming TCPv4 connection wasn't found in "
				  "fragments table -- saving it");

			if ((saved_packet = (char *) malloc(
			    sizeof(unsigned short) + sizeof(struct s_ethernet) +
			    sizeof(struct s_ipv4) + payload_size)) == NULL) {
				log_error("Lack of free memory");
				return 1;
			}

			/* if unsuccessful, create a queue and put into tree */
			if (frag_conn->queue == NULL) {
				if ((frag_conn->queue = linkedlist_create()) ==
				    NULL) {
					free(saved_packet);
					return 1;
				}
			}

			/* save the packet and put it into the queue */
			memcpy(saved_packet, &payload_size,
			       sizeof(unsigned short));
			memcpy(saved_packet + sizeof(unsigned short),
			       (char *) eth4, sizeof(struct s_ethernet) +
			       sizeof(struct s_ipv4));
			/* just in case the original IPv4 header had options */
			memcpy(saved_packet + sizeof(unsigned short) +
			       sizeof(struct s_ethernet) +
			       sizeof(struct s_ipv4), payload, payload_size);

			linkedlist_append(frag_conn->queue, saved_packet);

			return 0;
		}

		/* translated packet */
		eth6 = (struct s_ethernet *) packet;
		ip6  = (struct s_ipv6 *) (packet + sizeof(struct s_ethernet));
		frag = (struct s_ipv6_fragment *) (packet +
						   sizeof(struct s_ethernet) +
						   sizeof(struct s_ipv6));

		/* build ethernet header */
		eth6->dest		= frag_conn->connection->mac;
		eth6->src		= mac;
		eth6->type		= htons(ETHERTYPE_IPV6);

		/* build IPv6 header */
		ip6->ver		= 0x60 | (ip4->tos >> 4);
		ip6->traffic_class	= ip4->tos << 4;
		ip6->flow_label		= 0x0;
		ip6->hop_limit		= ip4->ttl;
		ip6->next_header	= IPPROTO_FRAGMENT;
		ipv4_to_ipv6(&ip4->ip_src, &ip6->ip_src);
		ip6->ip_dest		= frag_conn->connection->ipv6;

		/* build IPv6 fragment header */
		frag->next_header	= IPPROTO_TCP;
		frag->zeros		= 0x0;
		frag->id		= htonl(ntohs(ip4->id));

		/* fragment the fragment or not? */
		if (payload_size > mtu - sizeof(struct s_ipv6) -
		    sizeof(struct s_ipv6_fragment)) {
			/* fill in missing IPv6 header fields */
			ip6->len = htons(FRAGMENT_LEN +
					 sizeof(struct s_ipv6_fragment));

			/* fill in missing IPv6 fragment header fields */
			frag->offset_flag = htons((ntohs(ip4->flags_offset) <<
						   3) |
						  IPV6_FLAG_MORE_FRAGMENTS);

			/* copy the payload data */
			memcpy((char *) frag + sizeof(struct s_ipv6_fragment),
			       payload, FRAGMENT_LEN);

			/* send translated packet */
			transmit_raw(packet, sizeof(struct s_ethernet) + mtu);

			/* create the second fragment */
			ip6->len = htons(payload_size +
					 sizeof(struct s_ipv6_fragment) -
					 FRAGMENT_LEN);
			frag->offset_flag = htons(((ntohs(ip4->flags_offset) &
						    0x1fff) +
						   FRAGMENT_LEN / 8) << 3);
			if (ip4->flags_offset &
			    htons(IPV4_FLAG_MORE_FRAGMENTS)) {
				frag->offset_flag |=
					htons(IPV6_FLAG_MORE_FRAGMENTS);
			}

			/* copy the payload data */
			memcpy((char *) frag + sizeof(struct s_ipv6_fragment),
			       payload + FRAGMENT_LEN,
			       payload_size - FRAGMENT_LEN);

			/* send translated packet */
			transmit_raw(packet, sizeof(struct s_ethernet) +
					     sizeof(struct s_ipv6) +
					     sizeof(struct s_ipv6_fragment) -
					     FRAGMENT_LEN + payload_size);
		} else {
			/* fill in missing IPv6 header fields */
			ip6->len = htons(payload_size +
					 sizeof(struct s_ipv6_fragment));

			/* fill in missing IPv6 fragment header fields */
			frag->offset_flag = htons(ntohs(ip4->flags_offset) <<
						  3);
			if (ip4->flags_offset &
			    htons(IPV4_FLAG_MORE_FRAGMENTS)) {
				frag->offset_flag |=
					htons(IPV6_FLAG_MORE_FRAGMENTS);
			}

			/* copy the payload data */
			memcpy((char *) ip6 + sizeof(struct s_ipv6) +
			       sizeof(struct s_ipv6_fragment),
			       payload, payload_size);

			/* send translated packet */
			transmit_raw(packet, sizeof(struct s_ethernet) +
				     sizeof(struct s_ipv6) +
				     sizeof(struct s_ipv6_fragment) +
				     payload_size);
		}
	}

	return 0;
}

/**
 * Processing of outgoing TCPv6 packets. Directly sends translated TCPv4
 * packets.
 *
 * @param	eth6		Ethernet header
 * @param	ip6		IPv6 header
 * @param	payload		TCPv6 data
 * @param	payload_size	Size of the data payload (L4+)
 *
 * @return	0 for success
 * @return	1 for failure
 */
int tcp_ipv6(struct s_ethernet *eth6, struct s_ipv6 *ip6, char *payload,
	     unsigned short payload_size)
{
	struct s_tcp	*tcp;
	struct s_nat	*connection;
	unsigned short	 orig_checksum;
	struct s_ipv4	*ip4;
	char		 packet[PACKET_BUFFER];

	/* sanity check */
	if (payload_size < sizeof(struct s_tcp)) {
		log_debug("Too short TCPv6 packet");
		return 1;
	}

	/* parse TCP header */
	tcp = (struct s_tcp *) payload;

	/* checksum recheck */
	orig_checksum = tcp->checksum;
	tcp->checksum = 0;
	tcp->checksum = checksum_ipv6(ip6->ip_src, ip6->ip_dest,
				      payload_size, IPPROTO_TCP,
				      (char *) payload);

	if (tcp->checksum != orig_checksum) {
		/* packet is corrupted and shouldn't be processed */
		log_debug("Wrong checksum");
		return 1;
	}

	/* find connection in NAT */
	connection = nat_out(nat6_tcp, nat4_tcp, eth6->src,
			     ip6->ip_src, ip6->ip_dest,
			     tcp->port_src, tcp->port_dest,
			     tcp->flags & TCP_FLAG_SYN);

	if (connection == NULL) {
		log_warn("Outgoing connection wasn't found/created in NAT");
		return 1;
	}

	/* TCP state machine */
	switch (connection->state) {
		case TCP_STATE_EST:
			if (tcp->flags & TCP_FLAG_FIN) {
				connection->state = TCP_STATE_FIN6;
				break;
			} else if (tcp->flags & TCP_FLAG_RST) {
				connection->state = TCP_STATE_TRANS;
				linkedlist_move2end(timeout_tcp_trans,
						    connection->llnode);
				break;
			} else {
				linkedlist_move2end(timeout_tcp_est,
						    connection->llnode);
				break;
			}

		case TCP_STATE_INIT:
			if (tcp->flags & TCP_FLAG_SYN) {
				if (connection->llnode == NULL) {
					connection->llnode =
						linkedlist_append(
							timeout_tcp_trans,
							connection);
					break;
				} else {
					linkedlist_move2end(timeout_tcp_trans,
							    connection->llnode);
					break;
				}
			}
			break;

		case TCP_STATE_FIN4:
			if (tcp->flags & TCP_FLAG_FIN) {
				connection->state = TCP_STATE_FIN64;
				linkedlist_move2end(timeout_tcp_trans,
						    connection->llnode);
				break;
			} else {
				linkedlist_move2end(timeout_tcp_est,
						    connection->llnode);
				break;
			}

		case TCP_STATE_FIN6:
			linkedlist_move2end(timeout_tcp_est,
					    connection->llnode);
			break;

		case TCP_STATE_FIN64:
			break;

		case TCP_STATE_TRANS:
			if (tcp->flags & TCP_FLAG_RST) {
				break;
			} else {
				connection->state = TCP_STATE_EST;
				linkedlist_move2end(timeout_tcp_est,
						    connection->llnode);
				break;
			}
	}

	/* translated packet */
	ip4 = (struct s_ipv4 *) packet;

	/* build IPv4 packet */
	ip4->ver_hdrlen	  = 0x45;		/* ver 4, header length 20 B */
	ip4->tos	  = ((ip6->ver & 0x0f) << 4) |
			    ((ip6->traffic_class & 0xf0) >> 4);
	ip4->len	  = htons(sizeof(struct s_ipv4) + payload_size);
	ip4->id		  = 0x0;
	ip4->flags_offset = htons(IPV4_FLAG_DONT_FRAGMENT);
	ip4->ttl	  = ip6->hop_limit;
	ip4->proto	  = IPPROTO_TCP;
	ip4->ip_src	  = wrapsix_ipv4_addr;
	ipv6_to_ipv4(&ip6->ip_dest, &ip4->ip_dest);

	/* set outgoing source port */
	tcp->port_src = connection->ipv4_port_src;

	/* compute TCP checksum */
	tcp->checksum = checksum_ipv4_update(tcp->checksum,
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
	transmit_ipv4(&ip4->ip_dest, packet, sizeof(struct s_ipv4) +
		      payload_size);

	return 0;
}
