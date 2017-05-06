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

#ifndef CHECKSUM_H
#define CHECKSUM_H

#include "ipv4.h"
#include "ipv6.h"

unsigned short checksum(const void *data, int length);
unsigned short checksum_update(unsigned short old_sum,
			       unsigned short *old_data, short old_len,
			       unsigned short *new_data, short new_len);
unsigned short checksum_ipv4(struct s_ipv4_addr ip_src,
			     struct s_ipv4_addr ip_dest, unsigned short length,
			     unsigned char proto, char *payload);
unsigned short checksum_ipv6(struct s_ipv6_addr ip_src,
			     struct s_ipv6_addr ip_dest, unsigned short length,
			     unsigned char proto, char *payload);
unsigned short checksum_ipv4_update(unsigned short old_sum,
				    struct s_ipv6_addr ip6_src,
				    struct s_ipv6_addr ip6_dest,
				    unsigned short old_port,
				    struct s_ipv4_addr ip4_src,
				    struct s_ipv4_addr ip4_dest,
				    unsigned short new_port);
unsigned short checksum_ipv6_update(unsigned short old_sum,
				    struct s_ipv4_addr ip4_src,
				    struct s_ipv4_addr ip4_dest,
				    unsigned short old_port,
				    struct s_ipv6_addr ip6_src,
				    struct s_ipv6_addr ip6_dest,
				    unsigned short new_port);

#endif /* CHECKSUM_H */
