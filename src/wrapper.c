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

#define _DEFAULT_SOURCE

#include <arpa/inet.h>		/* inet_pton */
#include <linux/ethtool.h>	/* struct ethtool_value, ETHTOOL_S* */
#include <linux/if_ether.h>	/* ETH_P_ALL */
#include <linux/sockios.h>	/* SIOCETHTOOL */
#include <net/ethernet.h>	/* ETHERTYPE_* */
#include <net/if.h>		/* struct ifreq */
#include <netinet/in.h>		/* htons */
#include <netpacket/packet.h>	/* struct packet_mreq, struct sockaddr_ll */
#include <stdio.h>		/* perror */
#include <stdlib.h>		/* srand */
#include <string.h>		/* strncpy */
#include <sys/ioctl.h>		/* ioctl, SIOCGIFINDEX */
#include <sys/types.h>		/* caddr_t */
#include <time.h>		/* time, time_t */
#include <unistd.h>		/* close */

#include "arp.h"
#ifdef HAVE_CONFIG_H
#include "autoconfig.h"
#endif /* HAVE_CONFIG_H */
#include "config.h"
#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "log.h"
#include "nat.h"
#include "transmitter.h"
#include "wrapper.h"

unsigned short mtu;

struct ifreq		interface;
struct s_mac_addr	mac;
struct s_ipv6_addr	ndp_multicast_addr;
struct s_ipv6_addr	wrapsix_ipv6_prefix;
struct s_ipv4_addr	wrapsix_ipv4_addr;
struct s_ipv6_addr	host_ipv6_addr;
struct s_ipv4_addr	host_ipv4_addr;

static int process(char *packet, unsigned short length);

int main(int argc, char **argv)
{
	struct s_cfg_opts	cfg;

	struct packet_mreq	pmr;
	struct ethtool_value	ethtool;

	int	sniff_sock;
	int	length;
	char	buffer[PACKET_BUFFER];

	int	i;
	time_t	prevtime, curtime;

	log_info(PACKAGE_STRING " is starting");

	/* load configuration */
	if (argc == 1) {
		cfg_parse(SYSCONFDIR "/wrapsix.conf", &mtu, &cfg, 1);
	} else {
		cfg_parse(argv[1], &mtu, &cfg, 1);
	}

	log_info("Using: interface %s", cfg.interface);
	log_info("       prefix %s", cfg.prefix);
	log_info("       MTU %d", mtu);
	log_info("       IPv4 address %s", cfg.ipv4_address);

	/* get host IP addresses */
	if (cfg_host_ips(cfg.interface, &host_ipv6_addr, &host_ipv4_addr,
	    cfg.ipv4_address)) {
		log_error("Unable to get host IP addresses");
		return 1;
	}
	/* using block because of the temporary variable */
	{
		char ip_text[40];

		inet_ntop(AF_INET, &host_ipv4_addr, ip_text, sizeof(ip_text));
		log_info("       host IPv4 address %s", ip_text);
		inet_ntop(AF_INET6, &host_ipv6_addr, ip_text, sizeof(ip_text));
		log_info("       host IPv6 address %s", ip_text);
	}

	/* initialize the socket for sniffing */
	if ((sniff_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) ==
	    -1) {
		perror("socket");
		log_error("Unable to create listening socket");
		return 1;
	}

	/* get the interface */
	strncpy(interface.ifr_name, cfg.interface, IFNAMSIZ);
	if (ioctl(sniff_sock, SIOCGIFINDEX, &interface) == -1) {
		perror("ioctl");
		log_error("Unable to get the interface %s", cfg.interface);
		return 1;
	}

	/* get interface's HW address (i.e. MAC) */
	if (ioctl(sniff_sock, SIOCGIFHWADDR, &interface) == 0) {
		memcpy(&mac, &interface.ifr_hwaddr.sa_data,
		       sizeof(struct s_mac_addr));

		/* disable generic receive offload */
		ethtool.cmd = ETHTOOL_SGRO;
		ethtool.data = 0;
		interface.ifr_data = (caddr_t) &ethtool;
		if (ioctl(sniff_sock, SIOCETHTOOL, &interface) == -1) {
			perror("ioctl");
			log_warn("Unable to disable generic receive offload "
				 "on the interface");
		}

		/* disable tcp segmentation offload */
		ethtool.cmd = ETHTOOL_STSO;
		ethtool.data = 0;
		interface.ifr_data = (caddr_t) &ethtool;
		if (ioctl(sniff_sock, SIOCETHTOOL, &interface) == -1) {
			perror("ioctl");
			log_warn("Unable to disable tcp segmentation offload "
				 "on the interface");
		}

		/* reinitialize the interface */
		interface.ifr_data = NULL;
		if (ioctl(sniff_sock, SIOCGIFINDEX, &interface) == -1) {
			perror("ioctl");
			log_error("Unable to reinitialize the interface");
			return 1;
		}
	} else {
		perror("ioctl");
		log_error("Unable to get the interface's HW address");
		return 1;
	}

	/* bind the socket to the interface (isn't necessary in general, but
	 * lowpan doesn’t work without it) */
	if (setsockopt(sniff_sock, SOL_SOCKET, SO_BINDTODEVICE, &interface,
	    sizeof(struct ifreq)) == -1) {
		perror("setsockopt");
		log_error("Couldn't bind the sniffing socket to the "
			  "interface.");
		return 1;
	}

	/* set the promiscuous mode */
	memset(&pmr, 0x0, sizeof(pmr));
	pmr.mr_ifindex = interface.ifr_ifindex;
	pmr.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(sniff_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
	    (char *) &pmr, sizeof(pmr)) == -1) {
		perror("setsockopt");
		log_error("Unable to set the promiscuous mode on the "
			  "interface");
		return 1;
	}

	/* some preparations */
	/* compute binary IPv6 address of NDP multicast */
	inet_pton(AF_INET6, "ff02::1:ff00:0", &ndp_multicast_addr);

	/* compute binary IPv6 address of WrapSix prefix */
	inet_pton(AF_INET6, cfg.prefix, &wrapsix_ipv6_prefix);

	/* compute binary IPv4 address of WrapSix */
	inet_pton(AF_INET, cfg.ipv4_address, &wrapsix_ipv4_addr);

	/* initiate sending socket */
	if (transmission_init()) {
		log_error("Unable to initiate sending socket");
		return 1;
	}

	/* initiate NAT tables */
	nat_init();

	/* initiate random numbers generator */
	srand((unsigned int) time(NULL));

	/* initialize time */
	prevtime = time(NULL);

	/* sniff! :c) */
	for (i = 1;; i++) {
		length = recv(sniff_sock, buffer, PACKET_BUFFER, MSG_TRUNC);
		if (length == -1) {
			perror("recv");
			log_error("Unable to retrieve data from socket");
			return 1;
		}

		if (length > PACKET_BUFFER) {
			log_error("Received packet is too big (%d B). Please "
				  "tune NIC offloading features and report "
				  "this issue to " PACKAGE_BUGREPORT, length);
			continue;
		}

		process(buffer, length);

		if (i % 250000) {
			curtime = time(NULL);
			/* 2 seconds is minimum normal timeout */
			if ((curtime - prevtime) >= 2) {
				nat_cleaning();
				prevtime = curtime;
			}
			i = 0;
		}
	}

	/* clean-up */
	/* close sending socket */
	transmission_quit();

	/* empty NAT tables */
	nat_quit();

	/* unset the promiscuous mode */
	if (setsockopt(sniff_sock, SOL_PACKET, PACKET_DROP_MEMBERSHIP,
	    (char *) &pmr, sizeof(pmr)) == -1) {
		perror("setsockopt");
		log_error("Unable to unset the promiscuous mode on the "
			  "interface");
		/* do not call return here as we want to close the socket too */
	}

	/* close the socket */
	close(sniff_sock);

	return 0;
}

/**
 * Decide what to do with a packet and pass it for further processing.
 *
 * @param	packet	Packet data
 * @param	length	Packet data length
 *
 * @return	0 for success
 * @return	1 for failure
 */
static int process(char *packet, unsigned short length)
{
	struct s_ethernet *eth;

	/* sanity check: out of every combination this is the smallest one */
	if (length < sizeof(struct s_ethernet) + sizeof(struct s_ipv4) +
	    sizeof(struct s_icmp)) {
		return 1;
	}

	/* parse ethernet header */
	eth = (struct s_ethernet *) packet;

	#define payload		packet + sizeof(struct s_ethernet)
	#define payload_length	length - sizeof(struct s_ethernet)

	switch (htons(eth->type)) {
		case ETHERTYPE_IP:
			return ipv4(eth, payload, payload_length);
		case ETHERTYPE_IPV6:
			return ipv6(eth, payload, payload_length);
		case ETHERTYPE_ARP:
			return arp(eth, payload, payload_length);
		default:
			log_debug("HW Protocol: unknown [%d/0x%04x]",
			       htons(eth->type), htons(eth->type));
			return 1;
	}

	#undef payload_length
	#undef payload
}

/**
 * Translator of IPv6 address with embedded IPv4 address to that IPv4 address.
 *
 * @param	ipv6_addr	IPv6 address (as data source)
 * @param	ipv4_addr	Where to put final IPv4 address
 */
void ipv6_to_ipv4(struct s_ipv6_addr *ipv6_addr, struct s_ipv4_addr *ipv4_addr)
{
	memcpy(ipv4_addr, ipv6_addr->addr + 12, 4);
}

/**
 * Translator of IPv4 address to IPv6 address with WrapSix' prefix.
 *
 * @param	ipv4_addr	IPv4 address (as data source)
 * @param	ipv6_addr	Where to put final IPv6 address
 */
void ipv4_to_ipv6(struct s_ipv4_addr *ipv4_addr, struct s_ipv6_addr *ipv6_addr)
{
	memcpy(ipv6_addr, &wrapsix_ipv6_prefix, 12);
	memcpy(ipv6_addr->addr + 12, ipv4_addr, 4);
}
