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
#include <string.h>		/* memcpy, memset */

#include "checksum.h"
#include "icmp.h"
#include "ipv6.h"
#include "linkedlist.h"
#include "log.h"
#include "nat.h"
#include "tcp.h"
#include "transmitter.h"
#include "udp.h"
#include "wrapper.h"

/* declarations */
int sub_icmp4_error(char *payload, unsigned short payload_size,
		    char *packet, unsigned short *packet_len,
		    struct s_icmp **icmp, struct s_nat **connection);
int sub_icmp6_error(struct s_ethernet *eth6,
		    char *payload, unsigned short payload_size,
		    char *packet, unsigned short *packet_len,
		    struct s_icmp **icmp, struct s_nat **connection);

/**
 * Processing of incoming ICMPv4 packets. Directly sends translated ICMPv6
 * packets.
 *
 * @param	eth4		Ethernet header
 * @param	ip4		IPv4 header
 * @param	payload		ICMPv4 data
 * @param	payload_size	Size of the data payload
 *
 * @return	0 for success
 * @return	1 for failure
 */
int icmp_ipv4(struct s_ethernet *eth4, struct s_ipv4 *ip4, char *payload,
	      unsigned short payload_size)
{
	struct s_icmp	*icmp;
	unsigned int	*icmp_extra;
	unsigned short	*icmp_extra_s;
	char		*icmp_extra_c;
	char		*icmp_data;
	struct s_nat	*connection;
	unsigned short	 orig_checksum;
	char		 packet[PACKET_BUFFER];
	unsigned short	 new_len = sizeof(struct s_ethernet) +
				   sizeof(struct s_ipv6);

	struct s_icmp_echo *echo;
	struct s_ethernet *eth6;
	struct s_ipv6 *ip6;

	/* for error messages */
	struct s_ipv4 *eip4;
	struct s_ipv6 *eip6;

	/* sanity check */
	if (payload_size < sizeof(struct s_icmp) + 4) {
		log_debug("Too short ICMPv4 packet");
		return 1;
	}

	icmp = (struct s_icmp *) payload;
	icmp_data = payload + sizeof(struct s_icmp);

	/* ICMP checksum recheck */
	orig_checksum = icmp->checksum;
	icmp->checksum = 0x0;
	icmp->checksum = checksum((char *) icmp, payload_size);

	if (icmp->checksum != orig_checksum) {
		/* packet is corrupted and shouldn't be processed */
		log_debug("Wrong checksum");
		return 1;
	}

	switch (icmp->type) {
		case ICMPV4_ECHO_REPLY:
			/* this option is already sanitized */

			echo = (struct s_icmp_echo *) icmp_data;

			connection = nat_in(nat4_icmp, ip4->ip_src,
					    0, echo->id);

			if (connection == NULL) {
				log_debug("Incoming connection wasn't found in "
					  "NAT");
				return 1;
			}

			linkedlist_move2end(timeout_icmp, connection->llnode);

			echo->id = connection->ipv6_port_src;

			/* override information in the original ICMP header */
			icmp->type = ICMPV6_ECHO_REPLY;

			/* copy the payload data */
			if (payload_size < mtu - sizeof(struct s_ipv6)) {
				memcpy(packet + new_len, payload, payload_size);
				icmp = (struct s_icmp *) (packet + new_len);
				new_len += payload_size;
			} else {
				memcpy(packet + new_len, payload, mtu -
				       sizeof(struct s_ipv6));
				icmp = (struct s_icmp *) (packet + new_len);
				new_len += mtu - sizeof(struct s_ipv6);
			}

			break;

		case ICMPV4_DST_UNREACHABLE:
			if (icmp->code <= 13 || icmp->code == 15) {
				if (sub_icmp4_error(icmp_data + 4,
				    payload_size - sizeof(struct s_icmp) - 4,
				    packet, &new_len, &icmp, &connection)) {
					/* something went wrong */
					return 1;
				}

				eip4 = (struct s_ipv4 *) (icmp_data + 4);
				eip6 = (struct s_ipv6 *) (packet +
					sizeof(struct s_ethernet) +
					sizeof(struct s_ipv6) +
					sizeof(struct s_icmp) + 4);

				/* translate ICMP type&code */
				if (icmp->code == 2) {
					icmp->type = ICMPV6_PARAM_PROBLEM;
					icmp->code = 1;
					icmp_extra = (unsigned int *)
						((char *) icmp +
						 sizeof(struct s_icmp));
					if (eip6->next_header ==
					    IPPROTO_FRAGMENT) {
						/* field next_header in FragH */
						*icmp_extra = htonl(40);
					} else {
						/* field next_header in IPv6 */
						*icmp_extra = htonl(6);
					}
				} else if (icmp->code == 4) {
					icmp->type = ICMPV6_PKT_TOO_BIG;
					icmp->code = 0;
					/* here to write new 4B MTU value */
					icmp_extra = (unsigned int *)
						((char *) icmp +
						 sizeof(struct s_icmp));
					/* from here read original 2B MTU value
					 * after skipping 2 unused bytes */
					icmp_extra_s = (unsigned short *)
						((char *) icmp +
						 sizeof(struct s_icmp) + 2);
					/* router supports path MTU discovery */
					if (ntohs(*icmp_extra_s) >= 68) {
						*icmp_extra = htonl(
							ntohs(*icmp_extra_s) +
							20 < mtu ?
							(unsigned int)
							(ntohs(*icmp_extra_s) +
							20) :
							(unsigned int) mtu);
					/* does not => leverage packet length */
					} else {
						/* RFC1191 */
						/* NOTE: >= would cause infinite
						 * loop */
						/* 1492+ don't have to be
						 * checked -- the biggest packet
						 * we can send there is 1480 */
						if (ntohs(eip4->len) >
						    1006) {
							*icmp_extra =
								htonl(1006 +
								      20);
						} else if (ntohs(eip4->len) >
						    508) {
							*icmp_extra =
								htonl(508 + 20);
						} else if (ntohs(eip4->len) >
						    296) {
							*icmp_extra =
								htonl(296 + 20);
						} else {
							*icmp_extra =
								htonl(68 + 20);
						}
					}
				} else if (icmp->code == 3) {
					icmp->type = ICMPV6_DST_UNREACHABLE;
					icmp->code = 4;
				} else if (icmp->code == 9 ||
					   icmp->code == 10 ||
					   icmp->code == 13 ||
					   icmp->code == 15) {
					icmp->type = ICMPV6_DST_UNREACHABLE;
					icmp->code = 1;
				} else {
					icmp->type = ICMPV6_DST_UNREACHABLE;
					icmp->code = 0;
				}

				/* new packet is almost finished, yay! */

				break;
			} else {
				/* silently drop */
				return 0;
			}

		case ICMPV4_TIME_EXCEEDED:
			if (sub_icmp4_error(icmp_data + 4,
			    payload_size - sizeof(struct s_icmp) - 4,
			    packet, &new_len, &icmp, &connection)) {
				/* something went wrong */
				return 1;
			}

			icmp->type = ICMPV6_TIME_EXCEEDED;

			/* new packet is almost finished, yay! */

			break;

		case ICMPV4_PARAM_PROBLEM:
			if (icmp->code == 0 || icmp->code == 2) {
				/* update the extra field */
				icmp_extra = (unsigned int *)
					     ((char *) icmp +
					      sizeof(struct s_icmp));
				icmp_extra_c = (char *) icmp_extra;
				switch (*icmp_extra_c) {
					case 0:
					case 1:
						break;

					case 2:
					case 3:
						*icmp_extra = htonl(4);
						break;

					case 8:
						*icmp_extra = htonl(7);
						break;

					case 9:
						*icmp_extra = htonl(6);
						break;

					case 12:
					case 13:
					case 14:
					case 15:
						*icmp_extra = htonl(8);
						break;

					case 16:
					case 17:
					case 18:
					case 19:
						*icmp_extra = htonl(24);
						break;

					default:
						/* silently drop */
						return 0;
				}

				/* update type&code */
				icmp->type = ICMPV6_PARAM_PROBLEM;
				icmp->code = 0;

				/* translate body of the packet */
				if (sub_icmp4_error(icmp_data + 4,
				    payload_size - sizeof(struct s_icmp) - 4,
				    packet, &new_len, &icmp, &connection)) {
					/* something went wrong */
					return 1;
				}

				/* new packet is almost finished, yay! */
			} else {
				/* silently drop */
				return 0;
			}

			break;

		default:
			/* silently drop */
			return 0;
	}

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
	ip6->len		= htons(new_len - sizeof(struct s_ethernet) -
					sizeof(struct s_ipv6));
	ip6->next_header	= IPPROTO_ICMPV6;
	ip6->hop_limit		= ip4->ttl;
	ipv4_to_ipv6(&ip4->ip_src, &ip6->ip_src);
	ip6->ip_dest		= connection->ipv6;

	/* compute ICMP checksum; this is already in new packet */
	icmp->checksum = 0x0;
	icmp->checksum = checksum_ipv6(ip6->ip_src, ip6->ip_dest, new_len -
				       sizeof(struct s_ethernet) -
				       sizeof(struct s_ipv6), IPPROTO_ICMPV6,
				       (char *) icmp);

	/* send translated packet */
	transmit_raw(packet, new_len);

	return 0;
}

/**
 * Processing of outgoing ICMPv6 packets. Directly sends translated ICMPv4
 * packets.
 *
 * @param	eth6		Ethernet header
 * @param	ip6		IPv6 header
 * @param	payload		ICMPv6 data
 *
 * @return	0 for success
 * @return	1 for failure
 */
int icmp_ipv6(struct s_ethernet *eth6, struct s_ipv6 *ip6, char *payload)
{
	struct s_icmp 	*icmp;
	unsigned int	*icmp_extra;
	unsigned short	*icmp_extra_s;
	char		*icmp_extra_c;
	char	 	*icmp_data;
	struct s_nat  	*connection;
	unsigned short	 orig_checksum;
	unsigned short	 payload_size;
	char		 packet[PACKET_BUFFER - sizeof(struct s_ethernet)];
	unsigned short	 new_len = sizeof(struct s_ipv4);

	struct s_icmp_echo *echo;
	struct s_ipv4 *ip4;
	struct s_ipv6 *eip6;

	payload_size = ntohs(ip6->len);

	/* sanity check */
	if (payload_size < sizeof(struct s_icmp) + 4) {
		log_debug("Too short ICMPv6 packet");
		return 1;
	}

	icmp = (struct s_icmp *) payload;
	icmp_data = payload + sizeof(struct s_icmp);

	/* checksum recheck */
	orig_checksum = icmp->checksum;
	icmp->checksum = 0;
	icmp->checksum = checksum_ipv6(ip6->ip_src, ip6->ip_dest,
				       payload_size, IPPROTO_ICMPV6,
				       (char *) icmp);

	if (icmp->checksum != orig_checksum) {
		/* packet is corrupted and shouldn't be processed */
		log_debug("Wrong checksum");
		return 1;
	}

	/* decide the type of the ICMP packet */
	switch (icmp->type) {
		case ICMPV6_ECHO_REQUEST:
			/* this option is already sanitized */

			echo = (struct s_icmp_echo *) icmp_data;

			connection = nat_out(nat6_icmp, nat4_icmp, eth6->src,
					     ip6->ip_src, ip6->ip_dest,
					     echo->id, 0, 1);

			if (connection == NULL) {
				log_warn("Outgoing connection wasn't "
					 "found/created in NAT!");
				return 1;
			}

			if (connection->llnode == NULL) {
				connection->llnode =
					linkedlist_append(timeout_icmp,
							  connection);
			} else {
				linkedlist_move2end(timeout_icmp,
						    connection->llnode);
			}

			echo->id = connection->ipv4_port_src;

			/* override information in original ICMP header */
			icmp->type = ICMPV4_ECHO_REQUEST;

			icmp = (struct s_icmp *) (packet + new_len);

			/* copy the payload data */
			/* IPv6 node can handle too big packets itself */
			if (payload_size < 1500 - sizeof(struct s_ipv4)) {
				memcpy(icmp, payload, payload_size);
				new_len += payload_size;
			} else {
				memcpy(icmp, payload,
				       1500 - sizeof(struct s_ipv4));
				/* before new_len was only the size of s_ipv4 */
				new_len = 1500;
			}

			break;

		case ICMPV6_NDP_NS:
			/* sanity check */
			if (payload_size < sizeof(struct s_icmp) +
			    sizeof(struct s_icmp_ndp_ns)) {
				log_debug("Too short packet for NDP NS");
				return 1;
			}

			return icmp_ndp(eth6, ip6,
					(struct s_icmp_ndp_ns *) icmp_data);

		case ICMPV6_DST_UNREACHABLE:
			/* translate type */
			icmp->type = ICMPV4_DST_UNREACHABLE;

			/* translate code */
			if (icmp->code == 0 ||
			    icmp->code == 3 ||
			    icmp->code == 2) {
				icmp->code = 1;
			} else if (icmp->code == 1) {
				icmp->code = 10;
			} else if (icmp->code == 4) {
				icmp->code = 3;
			} else {
				/* silently drop */
				return 0;
			}

			/* translate body of the packet */
			if (sub_icmp6_error(eth6, icmp_data + 4,
			    payload_size - sizeof(struct s_icmp) - 4,
			    packet, &new_len, &icmp, &connection)) {
				/* something went wrong */
				return 1;
			}

			/* new packet is almost finished, yay! */

			break;

		case ICMPV6_TIME_EXCEEDED:
			/* translate type; code doesn't change */
			icmp->type = ICMPV4_TIME_EXCEEDED;

			/* translate body of the packet */
			if (sub_icmp6_error(eth6, icmp_data + 4,
			    payload_size - sizeof(struct s_icmp) - 4,
			    packet, &new_len, &icmp, &connection)) {
				/* something went wrong */
				return 1;
			}

			/* new packet is almost finished, yay! */

			break;

		case ICMPV6_PARAM_PROBLEM:
			if (icmp->code == 0) {
				/* update type; code remains unchanged */
				icmp->type = ICMPV4_PARAM_PROBLEM;

				/* update the extra field */
				icmp_extra = (unsigned int *)
					     ((char *) icmp +
					      sizeof(struct s_icmp));
				icmp_extra_c = (char *) icmp_extra;
				switch (*icmp_extra) {
					case 0:
					case 1:
						break;

					case 4:
					case 5:
						*icmp_extra_c = 2;
						break;

					case 6:
						*icmp_extra_c = 9;
						break;

					case 7:
						*icmp_extra_c = 8;
						break;

					default:
						/* 8-23 */
						if (*icmp_extra_c >= 8 &&
						    *icmp_extra_c <= 23) {
							*icmp_extra_c = 12;
						/* 24-39 */
						} else if (*icmp_extra_c > 23 &&
						    *icmp_extra_c <= 39) {
							*icmp_extra_c = 16;
						} else {
							/* silently drop */
							return 0;
						}
				}
			} else if (icmp->code == 1) {
				/* update type&code */
				icmp->type = ICMPV4_DST_UNREACHABLE;
				icmp->code = 2;
			} else {
				/* silently drop */
				return 0;
			}

			/* translate body of the packet */
			if (sub_icmp6_error(eth6, icmp_data + 4,
			    payload_size - sizeof(struct s_icmp) - 4,
			    packet, &new_len, &icmp, &connection)) {
				/* something went wrong */
				return 1;
			}

			/* new packet is almost finished, yay! */

			break;

		/* this shouldn't happen! it would mean MTU is set badly */
		case ICMPV6_PKT_TOO_BIG:
			log_warn("ICMPv6 'Packet too big' received. Your MTU "
				 "setting is too high!");

			/* sanity check */
			if (payload_size < sizeof(struct s_icmp) + 4 +
			    sizeof(struct s_ipv6)) {
				log_debug("Too short ICMPv6 packet"
					  "PacketTooBig");
				return 1;
			}

			eip6 = (struct s_ipv6 *) (icmp_data + 4);

			/* translate type&code */
			icmp->type = ICMPV4_DST_UNREACHABLE;
			icmp->code = 4;

			icmp_extra = (unsigned int *)
				((char *) icmp + sizeof(struct s_icmp));
			icmp_extra_s = (unsigned short *)
				((char *) icmp + sizeof(struct s_icmp) + 2);
			if (eip6->next_header != IPPROTO_FRAGMENT) {
				*icmp_extra_s = htons(ntohl(*icmp_extra) - 20);
			} else {
				/* D(IPv4, IPv6) - fragment header = 20 - 8 */
				*icmp_extra_s = htons(ntohl(*icmp_extra) - 12);
			}

			/* translate body of the packet */
			if (sub_icmp6_error(eth6, icmp_data + 4,
			    payload_size - sizeof(struct s_icmp) - 4,
			    packet, &new_len, &icmp, &connection)) {
				/* something went wrong */
				return 1;
			}

			/* new packet is almost finished, yay! */

			break;

		default:
			/* silently drop */
			return 0;
	}

	ip4 = (struct s_ipv4 *) packet;

	/* build IPv4 packet */
	ip4->ver_hdrlen	  = 0x45;		/* ver 4, header length 20 B */
	ip4->tos	  = ((ip6->ver & 0x0f) << 4) |
			    ((ip6->traffic_class & 0xf0) >> 4);
	ip4->len	  = htons(new_len);
	ip4->id		  = 0x0;
	ip4->flags_offset = htons(IPV4_FLAG_DONT_FRAGMENT);
	ip4->ttl	  = ip6->hop_limit;
	ip4->proto	  = IPPROTO_ICMP;
	ip4->ip_src	  = wrapsix_ipv4_addr;
	ipv6_to_ipv4(&ip6->ip_dest, &ip4->ip_dest);

	/* compute ICMP checksum */
	icmp->checksum = 0x0;
	icmp->checksum = checksum((char *) icmp, new_len -
				  sizeof(struct s_ipv4));

	/* compute IPv4 checksum */
	ip4->checksum = checksum_ipv4(ip4->ip_src, ip4->ip_dest,
				      new_len, IPPROTO_ICMP, (char *) icmp);

	/* send translated packet */
	transmit_ipv4(&ip4->ip_dest, packet, new_len);

	return 0;
}

/**
 * Processes NDP NS packets and sends NDP NA.
 *
 * @param	ethq		Ethernet header
 * @param	ipq		IPv6 header
 * @param	ndp_ns		NDP NS data
 *
 * @return	0 for success
 * @return	1 for failure
 */
int icmp_ndp(struct s_ethernet *ethq, struct s_ipv6 *ipq,
	     struct s_icmp_ndp_ns *ndp_ns)
{
	char			 packet[PACKET_BUFFER];
	struct s_ethernet	*ethr;
	struct s_ipv6		*ipr;
	struct s_icmp		*icmp;
	struct s_icmp_ndp_na	*ndp_na;

	/* first check whether the request belongs to us */
	if (memcmp(&wrapsix_ipv6_prefix, &ndp_ns->target, 12) != 0) {
		return 1;
	}

	/* prepare memory for reply packet */
	#define NDP_PACKET_SIZE sizeof(struct s_ethernet) + \
				sizeof(struct s_ipv6) + \
				sizeof(struct s_icmp) + \
				sizeof(struct s_icmp_ndp_na)
	memset(packet, 0x0, NDP_PACKET_SIZE);

	/* divide reply packet into parts */
	ethr	= (struct s_ethernet *)	   packet;
	ipr	= (struct s_ipv6 *)	   (packet + sizeof(struct s_ethernet));
	icmp	= (struct s_icmp *)	   (packet + sizeof(struct s_ethernet) +
					    sizeof(struct s_ipv6));
	ndp_na	= (struct s_icmp_ndp_na *) (packet + sizeof(struct s_ethernet) +
					    sizeof(struct s_ipv6) +
					    sizeof(struct s_icmp));

	/* ethernet */
	ethr->dest = ethq->src;
	ethr->src  = mac;
	ethr->type = ethq->type;

	/* IPv6 */
	ipr->ver = 0x60;
	ipr->len = htons(sizeof(struct s_icmp) + sizeof(struct s_icmp_ndp_na));
	ipr->next_header = IPPROTO_ICMPV6;
	/* hop limit 255 is required by RFC 4861, section 7.1.2. */
	ipr->hop_limit = 255;
	ipr->ip_src = ndp_ns->target;
	ipr->ip_dest = ipq->ip_src;

	/* ICMP */
	icmp->type = ICMPV6_NDP_NA;
	/* code = checksum = 0 by memset */

	/* NDP NA */
	ndp_na->flags	 = INNAF_S;
	ndp_na->target	 = ndp_ns->target;
	ndp_na->opt_type = 2;
	ndp_na->opt_len	 = 1;
	ndp_na->opt_tlla = ethr->src;

	/* compute ICMP checksum */
	icmp->checksum = checksum_ipv6(ipr->ip_src, ipr->ip_dest,
				       htons(ipr->len), IPPROTO_ICMPV6,
				       (char *) icmp);

	/* send NDP reply */
	transmit_raw(packet, NDP_PACKET_SIZE);

	return 0;
}

/**
 * Sends ICMPv4 error.
 *
 * @param	ip_dest	Destination IPv4 address
 * @param	type	Type of ICMP error
 * @param	code	Code of ICMP error
 * @param	data	Original packet
 * @param	length	Length of the original packet
 *
 * @return	0 for success
 * @return	1 for failure
 */
int icmp4_error(struct s_ipv4_addr ip_dest, unsigned char type,
		unsigned char code, char *data, unsigned short length)
{
	char		 packet[PACKET_BUFFER];
	char		*payload;
	unsigned int	*unused;
	struct s_ipv4	*ip4;
	struct s_icmp	*icmp;

	/* 4 = unused space after ICMP header */
	unsigned short payload_size = length > 1500 - sizeof(struct s_ipv4) -
					       sizeof(struct s_icmp) - 4 ?
		1500 - sizeof(struct s_ipv4) - sizeof(struct s_icmp) - 4 :
		length;

	ip4	= (struct s_ipv4 *) packet;
	icmp	= (struct s_icmp *) (packet + sizeof(struct s_ipv4));
	unused	= (unsigned int *)  (packet + sizeof(struct s_ipv4) +
				     sizeof(struct s_icmp));
	payload	= packet + sizeof(struct s_ipv4) + sizeof(struct s_icmp) + 4;

	/* build IPv4 packet */
	ip4->ver_hdrlen	  = 0x45;		/* ver 4, header length 20 B */
	ip4->tos	  = 0x0;
	ip4->len	  = htons(sizeof(struct s_ipv4) +
				  sizeof(struct s_icmp) + 4 + payload_size);
	ip4->id		  = 0x0;
	ip4->flags_offset = htons(IPV4_FLAG_DONT_FRAGMENT);
	ip4->ttl	  = 255;
	ip4->proto	  = IPPROTO_ICMP;
	ip4->ip_src	  = host_ipv4_addr;
	ip4->ip_dest	  = ip_dest;

	/* build ICMP header */
	icmp->type = type;
	icmp->code = code;
	icmp->checksum = 0x0;

	/* set unused area to zero */
	*unused = 0x0;

	/* copy the payload data */
	memcpy(payload, data, payload_size);

	/* compute ICMP checksum */
	icmp->checksum = checksum((char *) icmp,
				  payload_size + 4 + sizeof(struct s_icmp));

	/* compute IPv4 checksum */
	ip4->checksum = checksum_ipv4(ip4->ip_src, ip4->ip_dest,
				      htons(ip4->len), IPPROTO_ICMP,
				      (char *) icmp);

	/* send packet */
	transmit_ipv4(&ip4->ip_dest, packet, htons(ip4->len));

	return 0;
}

/**
 * Sends ICMPv6 error.
 *
 * @param	mac_dest Destination MAC address
 * @param	ip_dest	Destination IPv6 address
 * @param	type	Type of ICMP error
 * @param	code	Code of ICMP error
 * @param	data	Original packet
 * @param	length	Length of the original packet
 *
 * @return	0 for success
 * @return	1 for failure
 */
int icmp6_error(struct s_mac_addr mac_dest, struct s_ipv6_addr ip_dest,
		unsigned char type, unsigned char code, char *data,
		unsigned short length)
{
	char		   packet[PACKET_BUFFER];
	char		  *payload;
	unsigned int	  *unused;
	struct s_ethernet *eth;
	struct s_ipv6	  *ip6;
	struct s_icmp	  *icmp;

	/* 4 = unused space after ICMP header */
	/* 1280 -- because RFC on ICMPv6 says so */
	unsigned short payload_size = length > 1280 - sizeof(struct s_ipv6) -
					       sizeof(struct s_icmp) - 4 ?
		1280 - sizeof(struct s_ipv6) - sizeof(struct s_icmp) - 4 :
		length;

	eth	= (struct s_ethernet *)	packet;
	ip6	= (struct s_ipv6 *)	(packet + sizeof(struct s_ethernet));
	icmp	= (struct s_icmp *)	(packet + sizeof(struct s_ethernet) +
					 sizeof(struct s_ipv6));
	unused	= (unsigned int *)	(packet + sizeof(struct s_ethernet) +
					 sizeof(struct s_ipv6) +
					 sizeof(struct s_icmp));
	payload	= packet + sizeof(struct s_ethernet) + sizeof(struct s_ipv6) +
		  sizeof(struct s_icmp) + 4;

	/* ethernet */
	eth->dest = mac_dest;
	eth->src  = mac;
	eth->type = htons(ETHERTYPE_IPV6);

	/* IPv6 */
	ip6->ver	 = 0x60;
	ip6->len	 = htons(sizeof(struct s_icmp) + 4 + payload_size);
	ip6->next_header = IPPROTO_ICMPV6;
	ip6->hop_limit	 = 255;
	ip6->ip_src	 = host_ipv6_addr;
	ip6->ip_dest	 = ip_dest;

	/* ICMP */
	icmp->type = type;
	icmp->code = code;
	icmp->checksum = 0x0;

	/* set unused area to zero */
	*unused = 0x0;

	/* copy the payload data */
	memcpy(payload, data, payload_size);

	/* compute ICMP checksum */
	icmp->checksum = checksum_ipv6(host_ipv6_addr, ip_dest,
				       sizeof(struct s_icmp) + 4 + payload_size,
				       IPPROTO_ICMPV6, (char *) icmp);

	/* send packet */
	transmit_raw(packet, sizeof(struct s_ethernet) + sizeof(struct s_ipv6) +
		     sizeof(struct s_icmp) + 4 + payload_size);

	return 0;
}

/**
 * Helper function for translating inner packet in ICMPv4 error.
 *
 * @param	payload		Original inner packet data
 * @param	payload_size	Length of original data
 * @param	packet		Space for translated packet data
 * @param	packet_len	Length of translated data
 * @param	icmp		Outer ICMP header
 * @param	connection	NAT connection for inner packet
 *
 * @return	0 for success
 * @return	1 for failure
 */
int sub_icmp4_error(char *payload, unsigned short payload_size,
		    char *packet, unsigned short *packet_len,
		    struct s_icmp **icmp, struct s_nat **connection)
{
	struct s_ipv4		*eip4;
	struct s_ipv6		*eip6;
	struct s_tcp		*etcp;
	struct s_udp		*eudp;
	struct s_icmp		*eicmp;
	unsigned short		 eip4_hlen;
	struct s_ipv6_fragment	*eip6_frag;
	struct s_icmp_echo	*echo;

	/* sanity check */
	if (payload_size < 1) {
		log_debug("Too short ICMPv4 packet 2");
		return 1;
	}

	/* parse IPv4 header */
	eip4 = (struct s_ipv4 *) payload;

	/* # of 4 byte words */
	eip4_hlen = (eip4->ver_hdrlen & 0x0f) * 4;

	/* sanity check */
	/* 4 B -> L4 addrs */
	if (payload_size < eip4_hlen + 4) {
		log_debug("Too short ICMPv4 packet 3");
		return 1;
	}
	payload_size -= eip4_hlen;
	payload += eip4_hlen;

	/* define new inner IPv6 header */
	/* new_len+4+4+40=102 < 1280 */
	eip6 = (struct s_ipv6 *) (packet + *packet_len + sizeof(struct s_icmp) +
				  4);

	/* we'll need this right now */
	ipv4_to_ipv6(&eip4->ip_dest, &eip6->ip_dest);

	/* look for the original connection */
	switch (eip4->proto) {
		case IPPROTO_TCP:
			etcp = (struct s_tcp *) payload;
			*connection = nat_in(nat4_tcp, eip4->ip_dest,
					     etcp->port_dest, etcp->port_src);

			if (*connection == NULL) {
				log_debug("Incoming TCP error connection "
					  "wasn't found in NAT");
				return 1;
			}

			/* fix port for local client */
			etcp->port_src = (*connection)->ipv6_port_src;

			break;

		case IPPROTO_UDP:
			eudp = (struct s_udp *) payload;
			*connection = nat_in(nat4_udp, eip4->ip_dest,
					     eudp->port_dest, eudp->port_src);

			if (*connection == NULL) {
				log_debug("Incoming UDP error connection "
					  "wasn't found in NAT");
				return 1;
			}

			/* fix port for local client */
			eudp->port_src = (*connection)->ipv6_port_src;

			break;

		case IPPROTO_ICMP:
			eicmp = (struct s_icmp *) payload;

			/* we translate only echo requests so handle only them
			 * here too */
			if (eicmp->type != ICMPV4_ECHO_REQUEST) {
				log_debug("Unknown ICMP type within ICMP "
					  "error");
				return 1;
			}

			/* else: */

			/* sanity check */
			if (payload_size < sizeof(struct s_icmp) +
					   sizeof(struct s_icmp_echo)) {
				log_debug("Too short ICMPv4 packet 4");
				return 1;
			}

			echo = (struct s_icmp_echo *) (payload +
						       sizeof(struct s_icmp));

			*connection = nat_in(nat4_icmp, eip4->ip_dest, 0,
					     echo->id);

			if (*connection == NULL) {
				log_debug("Incoming ICMP error connection "
					  "wasn't found in NAT");
				return 1;
			}

			/* fix port for local client */
			echo->id = (*connection)->ipv6_port_src;

			/* adjust ICMP type */
			eicmp->type = ICMPV6_ECHO_REQUEST;

			break;

		default:
			/* we don't know where to send it */
			return 1;
	}

	/* copy ICMP header to new packet */
	memcpy(packet + *packet_len, (char *) *icmp, sizeof(struct s_icmp) + 4);
	*icmp = (struct s_icmp *) (packet + *packet_len);

	/* complete inner IPv6 header */
	eip6->ver = 0x60 | (eip4->tos >> 4);
	eip6->traffic_class = eip4->tos << 4;
	eip6->flow_label = 0x0;
	eip6->hop_limit = eip4->ttl;
	if (eip4->proto != IPPROTO_ICMP) {
		eip6->next_header = eip4->proto;
	} else {
		eip6->next_header = IPPROTO_ICMPV6;
	}
	eip6->ip_src = (*connection)->ipv6;

	*packet_len += sizeof(struct s_icmp) + 4 + sizeof(struct s_ipv6);

	/* was the IPv4 packet fragmented? */
	if (ntohs(eip4->flags_offset) & 0x1fff) {
		eip6_frag = (struct s_ipv6_fragment *) (packet + *packet_len);

		if (ntohs(eip4->flags_offset) & IPV4_FLAG_MORE_FRAGMENTS) {
			eip6_frag->offset_flag = htons(((ntohs(eip4->
				flags_offset) & 0x1fff) << 3) |
				IPV6_FLAG_MORE_FRAGMENTS);
		} else {
			eip6_frag->offset_flag = htons((ntohs(eip4->
				flags_offset) & 0x1fff) << 3);
		}

		/* original length of error packet, but without IP header,
		 * but with fragment header(!) */
		eip6->len = htons(ntohs(eip4->len) - eip4_hlen +
				  sizeof(struct s_ipv6_fragment));

		eip6_frag->next_header	= eip6->next_header;
		eip6_frag->id		= htonl(ntohs(eip4->id));
		eip6->next_header	= IPPROTO_FRAGMENT;

		*packet_len += sizeof(struct s_ipv6_fragment);
	} else {
		eip6->len = htons(ntohs(eip4->len) - eip4_hlen);
	}

	/* copy payload, aligned to MTU */
	/* we can afford to use full MTU instead of just 1280 B as admin
	 * warrants this to us */
	if (payload_size > mtu + sizeof(struct s_ethernet) - *packet_len) {
		memcpy(packet + *packet_len, payload,
		       mtu + sizeof(struct s_ethernet) - *packet_len);
		*packet_len = mtu + sizeof(struct s_ethernet);
	} else {
		memcpy(packet + *packet_len, payload, payload_size);
		*packet_len += payload_size;
	}

	return 0;
}

/**
 * Helper function for translating inner packet in ICMPv6 error.
 *
 * @param	eth6		Ethernet header of incoming packet
 * @param	payload		Original inner packet data
 * @param	payload_size	Length of original data
 * @param	packet		Space for translated packet data
 * @param	packet_len	Length of translated data
 * @param	icmp		Outer ICMP header
 * @param	connection	NAT connection for inner packet
 *
 * @return	0 for success
 * @return	1 for failure
 */
int sub_icmp6_error(struct s_ethernet *eth6,
		    char *payload, unsigned short payload_size,
		    char *packet, unsigned short *packet_len,
		    struct s_icmp **icmp, struct s_nat **connection)
{
	struct s_ipv4		*eip4;
	struct s_ipv6		*eip6;
	struct s_ipv6_fragment	*eip6_frag;
	struct s_tcp		*etcp;
	struct s_udp		*eudp;
	struct s_icmp		*eicmp;
	struct s_icmp_echo	*echo;

	unsigned char skip_l4 = 0;

	/* sanity check; redundant only for rare 'Packet too big' */
	if (payload_size < sizeof(struct s_ipv6)) {
		log_debug("Too short ICMPv6 packet 2");
		return 1;
	}

	eip6 = (struct s_ipv6 *) payload;
	payload += sizeof(struct s_ipv6);
	payload_size -= sizeof(struct s_ipv6);

	/* define new inner IPv4 header */
	/* new_len+4+4+20=48 < 576 */
	eip4 = (struct s_ipv4 *) (packet + *packet_len + sizeof(struct s_icmp) +
				  4);
	/* we'll need this right now */
	ipv6_to_ipv4(&eip6->ip_src, &eip4->ip_src);

	/* handle fragmented inner packets */
	if (eip6->next_header == IPPROTO_FRAGMENT) {
		/* sanity check */
		if (payload_size < sizeof(struct s_ipv6_fragment)) {
			log_debug("Too short ICMPv6 packet 4");
			return 1;
		}

		eip6_frag = (struct s_ipv6_fragment *) payload;

		eip4->id = htons(ntohl(eip6_frag->id));
		if (ntohs(eip6_frag->offset_flag) & 0xfff8) {
			/* this is not the first fragment */
			skip_l4 = 1;
		}
		if (ntohs(eip6_frag->offset_flag) & IPV6_FLAG_MORE_FRAGMENTS) {
			eip4->flags_offset = htons(((ntohs(eip6_frag->
				offset_flag) & 0xfff8) >> 3) |
				IPV4_FLAG_MORE_FRAGMENTS);
		} else {
			eip4->flags_offset = htons((ntohs(eip6_frag->
				offset_flag) & 0xfff8) >> 3);
		}
		eip6->next_header = eip6_frag->next_header;

		payload += sizeof(struct s_ipv6_fragment);
		payload_size -= sizeof(struct s_ipv6_fragment);
	} else {
		eip4->id	   = 0x0;
		eip4->flags_offset = htons(IPV4_FLAG_DONT_FRAGMENT);
	}

	/* look for the original connection */
	if (skip_l4 == 0) {
		/* sanity check */
		/* 4 B -> L4 addrs */
		if (payload_size < 4) {
			log_debug("Too short ICMPv6 packet 5");
			return 1;
		}

		switch (eip6->next_header) {
			case IPPROTO_TCP:
				etcp = (struct s_tcp *) payload;
				*connection = nat_out(nat6_tcp, nat4_tcp,
					eth6->src, eip6->ip_dest, eip6->ip_src,
					etcp->port_dest, etcp->port_src, 0);

				if (*connection == NULL) {
					log_debug("Outgoing TCP error "
						  "connection wasn't found in "
						  "NAT");
					return 1;
				}

				/* fix port for remote client */
				etcp->port_dest = (*connection)->ipv4_port_src;

				break;

			case IPPROTO_UDP:
				eudp = (struct s_udp *) payload;
				*connection = nat_out(nat6_udp, nat4_udp,
					eth6->src, eip6->ip_dest, eip6->ip_src,
					eudp->port_dest, eudp->port_src, 0);

				if (*connection == NULL) {
					log_debug("Outgoing UDP error "
						  "connection wasn't found in "
						  "NAT");
					return 1;
				}

				/* fix port for remote client */
				eudp->port_dest = (*connection)->ipv4_port_src;

				break;

			case IPPROTO_ICMP:
				eicmp = (struct s_icmp *) payload;

				/* we translate only echo replies so handle
				 * only them here too */
				if (eicmp->type != ICMPV6_ECHO_REPLY) {
					log_debug("Unknown ICMP type within "
						  "ICMP error");
					return 1;
				}

				/* else: */

				/* sanity check */
				if (payload_size < sizeof(struct s_icmp) +
				    sizeof(struct s_icmp_echo)) {
					log_debug("Too short ICMPv6 packet 3");
					return 1;
				}

				echo = (struct s_icmp_echo *) (payload +
					sizeof(struct s_icmp));

				*connection = nat_out(nat6_icmp, nat4_icmp,
					eth6->src, eip6->ip_dest, eip6->ip_src,
					echo->id, 0, 0);

				if (*connection == NULL) {
					log_debug("Incoming ICMP error "
						  "connection wasn't found in "
						  "NAT");
					return 1;
				}

				/* fix port for remote client */
				echo->id = (*connection)->ipv4_port_src;

				/* adjust ICMP type */
				eicmp->type = ICMPV4_ECHO_REPLY;

				break;

			default:
				/* anything else surely wasn't translated */
				return 1;
		}
	}

	/* copy ICMP header (with updated data) to new packet */
	memcpy(packet + *packet_len, *icmp, sizeof(struct s_icmp) + 4);
	*icmp = (struct s_icmp *) (packet + *packet_len);

	/* complete inner IPv4 header */
	eip4->ver_hdrlen  = 0x45;		/* ver 4, header length 20 B */
	eip4->tos	  = ((eip6->ver & 0x0f) << 4) |
			    ((eip6->traffic_class & 0xf0) >> 4);
	eip4->len	  = htons(sizeof(struct s_ipv4) + ntohs(eip6->len));
	eip4->ttl	  = eip6->hop_limit;
	eip4->ip_src	  = wrapsix_ipv4_addr;
	if (eip6->next_header != IPPROTO_ICMPV6) {
		eip4->proto = eip6->next_header;
	} else {
		eip4->proto = IPPROTO_ICMP;
	}

	/* packet_len == sizeof(outer IPv4 header) */
	*packet_len += sizeof(struct s_icmp) + 4 + sizeof(struct s_ipv4);

	/* copy payload */
	/* let's use 576 as an IPv4 MTU */
	if (payload_size > 576 - *packet_len) {
		memcpy(packet + *packet_len, payload, 576 - *packet_len);
		*packet_len = 576;
	} else {
		memcpy(packet + *packet_len, payload, payload_size);
		*packet_len += payload_size;
	}

	return 0;
}
