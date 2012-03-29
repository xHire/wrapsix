/*
 *  WrapSix
 *  Copyright (C) 2008-2012  Michal Zima <xhire@mujmalysvet.cz>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef WRAPPER_H
#define WRAPPER_H

#include "ipv4.h"
#include "ipv6.h"

extern struct ifreq		interface;
extern struct s_ipv6_addr	ndp_multicast_addr;
extern struct s_ipv6_addr	wrapsix_ipv6_prefix;

void ipv6_to_ipv4(struct s_ipv6_addr *ipv6_addr, struct s_ipv4_addr *ipv4_addr);
void ipv4_to_ipv6(struct s_ipv4_addr *ipv4_addr, struct s_ipv6_addr *ipv6_addr);

#endif /* WRAPPER_H */