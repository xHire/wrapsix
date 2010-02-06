/*
 *  WrapSix
 *  Copyright (C) 2008-2010  Michal Zima <xhire@mujmalysvet.cz>
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

#include <arpa/inet.h>		/* inet_pton */
#include <linux/if_ether.h>	/* ETH_P_ALL */
#include <net/if.h>		/* struct ifreq */
#include <netpacket/packet.h>	/* struct packet_mreq, struct sockaddr_ll */
#include <netinet/in.h>		/* htons */
#include <net/ethernet.h>	/* ETHERTYPE_* */
#include <stdio.h>
#include <string.h>		/* strncpy */
#include <sys/ioctl.h>		/* ioctl, SIOCGIFINDEX */
#include <unistd.h>		/* close */

#include "wrapper.h"

#define INTERFACE	"eth0"
#define BUFFER_SIZE	65536

int process(char *packet);

int main(int argc, char **argv)
{
	struct ifreq		interface;
	struct packet_mreq	pmr;

	struct sockaddr_ll	addr;
	size_t			addr_size;

	int	sniff_sock;
	int	length;
	char	buffer[BUFFER_SIZE];

	/* initialize the socket for sniffing */
	if ((sniff_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		fprintf(stderr, "[Error] Unable to create listening socket\n");
		return 1;
	}

	/* get the interface */
	strncpy(interface.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(sniff_sock, SIOCGIFINDEX, &interface) == -1) {
		fprintf(stderr, "[Error] Unable to get the interface\n");
		return 1;
	}

	/* set the promiscuous mode */
	memset(&pmr, 0x0, sizeof(pmr));
	pmr.mr_ifindex = interface.ifr_ifindex;
	pmr.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(sniff_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (char *) &pmr, sizeof(pmr)) == -1) {
		fprintf(stderr, "[Error] Unable to set the promiscuous mode on the interface\n");
		return 1;
	}

	/* sniff! :c) */
	for (;;) {
		addr_size = sizeof(addr);
		if ((length = recv(sniff_sock, buffer, BUFFER_SIZE, 0)) == -1) {
			fprintf(stderr, "[Error] Unable to retrieve data from socket\n");
			return 1;
		}

		process((char *) &buffer);
	}

	/* clean-up */
	/* unset the promiscuous mode */
	if (setsockopt(sniff_sock, SOL_PACKET, PACKET_DROP_MEMBERSHIP, (char *) &pmr, sizeof(pmr)) == -1) {
		fprintf(stderr, "[Error] Unable to unset the promiscuous mode on the interface\n");
		/* do not call `return` here as we want to close the socket too */
	}

	/* close the socket */
	close(sniff_sock);

	return 0;
}

int process(char *packet)
{
	struct s_ethernet	*eth;		/* the ethernet header */
	char			*payload;	/* the IP header + packet payload */

	/* parse ethernet header */
	eth     = (struct s_ethernet *) (packet);
	payload = packet + sizeof(struct s_ethernet);

	switch (htons(eth->type)) {
		case ETHERTYPE_IP:
			printf("[Debug] HW Protocol: IPv4\n");
			return -1;
		case ETHERTYPE_IPV6:
			printf("[Debug] HW Protocol: IPv6\n");
			return -1;
		case ETHERTYPE_ARP:
			printf("[Debug] HW Protocol: ARP\n");
			return -1;
		default:
			printf("[Debug] HW Protocol: unknown [%d/0x%04x]\n",
			       htons(eth->type), htons(eth->type));
			return 1;
	}
}
