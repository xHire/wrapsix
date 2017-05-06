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

#include <netinet/in.h>		/* htonl */
#include <string.h>		/* memcpy */

#include "checksum.h"
#include "ipv4.h"
#include "ipv6.h"
#include "log.h"
#include "wrapper.h"

/**
 * General checksum computation function.
 *
 * @param	data	Pointer to data of which to compute the checksum
 * @param	length	Length of the data (in bytes)
 *
 * @return	Checksum
 */
unsigned short checksum(const void *data, int length)
{
	const unsigned short *buf = data;
	unsigned int sum = 0;

	while (length >= 2) {
		sum += *buf++;

		if (sum & 0x80000000) {
			sum = (sum & 0xffff) + (sum >> 16);
		}

		length -= 2;
	}

	if (length) {
		char temp[2];

		temp[0] = *(char *) buf;
		temp[1] = 0;

		sum += *(unsigned short *) temp;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

/**
 * General checksum update computation function. Inspired by algorithm
 * in RFC3022.
 *
 * @param	old_sum		Old checksum
 * @param	old_data	Pointer to old part of data. Must be of even
 * 				number of octets
 * @param	old_len		Length of old data
 * @param	new_data	Pointer to new part of data. Must be of even
 * 				number of octets
 * @param	new_len		Length of new data
 *
 * @return	Updated checksum
 */
unsigned short checksum_update(unsigned short old_sum,
			       unsigned short *old_data, short old_len,
			       unsigned short *new_data, short new_len)
{
	unsigned int sum;

	sum = ~old_sum & 0xffff;

	while (old_len) {
		sum -= *old_data++;
		if (sum & 0x80000000) {
			sum--;
			sum &= 0xffff;
		}
		old_len -= 2;
	}

	while (new_len) {
		sum += *new_data++;
		if (sum & 0x00010000) {
			sum++;
			sum &= 0xffff;
		}
		new_len -= 2;
	}

	return ~sum & 0xffff;
}

/**
 * IPv4 checksum computation function.
 *
 * @param	ip_src	Source IPv4 address
 * @param	ip_dest	Destination IPv4 address
 * @param	length	Length of the payload (in bytes)
 * @param	proto	Protocol in the payload
 * @param	payload	Pointer to payload data
 *
 * @return	Checksum
 */
unsigned short checksum_ipv4(struct s_ipv4_addr ip_src,
			     struct s_ipv4_addr ip_dest,
			     unsigned short length, unsigned char proto,
			     char *payload)
{
	char			 buffer[PACKET_BUFFER];
	struct s_ipv4_pseudo	*header;

	header = (struct s_ipv4_pseudo *) buffer;

	header->ip_src	= ip_src;
	header->ip_dest = ip_dest;
	header->zeros	= 0x0;
	header->proto	= proto;
	header->len	= htons(length);

	memcpy(buffer + sizeof(struct s_ipv4_pseudo), payload, (int) length);

	return checksum(buffer, sizeof(struct s_ipv4_pseudo) + (int) length);
}

/**
 * IPv6 checksum computation function.
 *
 * @param	ip_src	Source IPv6 address
 * @param	ip_dest	Destionation IPv6 address
 * @param	length	Length of the payload (in bytes)
 * @param	proto	Protocol in the payload
 * @param	payload	Pointer to payload data
 *
 * @return	Checksum
 */
unsigned short checksum_ipv6(struct s_ipv6_addr ip_src,
			     struct s_ipv6_addr ip_dest,
			     unsigned short length, unsigned char proto,
			     char *payload)
{
	char			 buffer[PACKET_BUFFER];
	struct s_ipv6_pseudo	*header;

	header = (struct s_ipv6_pseudo *) buffer;

	header->ip_src	    = ip_src;
	header->ip_dest	    = ip_dest;
	header->len	    = htonl((unsigned int) length);
	header->zeros	    = 0x0;
	header->next_header = proto;

	memcpy(buffer + sizeof(struct s_ipv6_pseudo), payload, (int) length);

	return checksum(buffer, sizeof(struct s_ipv6_pseudo) + (int) length);
}

/**
 * IPv4 checksum update computation function.
 *
 * @param	old_sum		Old checksum
 * @param	ip6_src		Original source IPv6 address
 * @param	ip6_dest	Original destination IPv6 address
 * @param	old_port	Original transport layer address (port)
 * @param	ip4_src		New source IPv4 address
 * @param	ip4_dest	New destination IPv4 address
 * @param	new_port	New transport layer address (port)
 *
 * @return	Checksum
 */
unsigned short checksum_ipv4_update(unsigned short old_sum,
				    struct s_ipv6_addr ip6_src,
				    struct s_ipv6_addr ip6_dest,
				    unsigned short old_port,
				    struct s_ipv4_addr ip4_src,
				    struct s_ipv4_addr ip4_dest,
				    unsigned short new_port)
{
	struct s_ipv4_pseudo_delta delta4;
	struct s_ipv6_pseudo_delta delta6;

	delta4.ip_src	= ip4_src;
	delta4.ip_dest	= ip4_dest;
	delta4.port	= new_port;

	delta6.ip_src	= ip6_src;
	delta6.ip_dest	= ip6_dest;
	delta6.port	= old_port;

	return checksum_update(old_sum,
			       (unsigned short *) &delta6,
			       sizeof(struct s_ipv6_pseudo_delta),
			       (unsigned short *) &delta4,
			       sizeof(struct s_ipv4_pseudo_delta));
}

/**
 * IPv6 checksum update computation function.
 *
 * @param	old_sum		Old checksum
 * @param	ip4_src		Original source IPv4 address
 * @param	ip4_dest	Original destination IPv4 address
 * @param	old_port	Original transport layer address (port)
 * @param	ip6_src		New source IPv6 address
 * @param	ip6_dest	New destination IPv6 address
 * @param	new_port	New transport layer address (port)
 *
 * @return	Checksum
 */
unsigned short checksum_ipv6_update(unsigned short old_sum,
				    struct s_ipv4_addr ip4_src,
				    struct s_ipv4_addr ip4_dest,
				    unsigned short old_port,
				    struct s_ipv6_addr ip6_src,
				    struct s_ipv6_addr ip6_dest,
				    unsigned short new_port)
{
	struct s_ipv4_pseudo_delta delta4;
	struct s_ipv6_pseudo_delta delta6;

	delta4.ip_src	= ip4_src;
	delta4.ip_dest	= ip4_dest;
	delta4.port	= old_port;

	delta6.ip_src	= ip6_src;
	delta6.ip_dest	= ip6_dest;
	delta6.port	= new_port;

	return checksum_update(old_sum,
			       (unsigned short *) &delta4,
			       sizeof(struct s_ipv4_pseudo_delta),
			       (unsigned short *) &delta6,
			       sizeof(struct s_ipv6_pseudo_delta));
}
