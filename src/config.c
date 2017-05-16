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

#include <arpa/inet.h>	/* inet_pton */
#include <ifaddrs.h>	/* struct ifaddrs, getifaddrs, freeifaddrs */
#include <netdb.h>	/* getnameinfo, NI_NUMERICHOST */
#include <stdio.h>	/* FILE, fopen, getc, feof, fclose, perror */
#include <stdlib.h>	/* exit */
#include <string.h>	/* strcmp, strncpy */

#include "config.h"
#include "ipv4.h"
#include "ipv6.h"
#include "log.h"
#include "wrapper.h"

#define SYNTAX_ERROR(file, line, pos, fatal) { \
			log_error("Syntax error in configuration file %s on " \
				  "line %d, position %d", file, line, pos); \
			fclose(f); \
			if (fatal) { \
				exit(1); \
			} else { \
				return 1; \
			} \
		}

#define	C_DEFAULT_MTU		1280
#define	C_DEFAULT_PREFIX	"64:ff9b::"

void cfg_guess_interface(char *cinterface);

/**
 * Configuration file parser.
 *
 * @param	config_file	Configuration file (with path) to parse
 * @param	cmtu		Pointer to variable where to save MTU
 * @param	oto		One-time configuration options (used only
 * 				locally to init other things)
 * @param	init		0 or 1, whether or not to initialize
 * 				configuration with defaults
 *
 * @return      0 for success
 * @return      1 for failure in case of some syntax error when reloading
 * 		configuration
 * @return	exit with code 1 in case of some syntax error when initializing
 * 		configuration
 */
int cfg_parse(const char *config_file, unsigned short *cmtu,
	      struct s_cfg_opts *oto, unsigned char init)
{
	FILE *f;
	unsigned int ln = 0;
	char c;

	unsigned short opt_len, wht_len, val_len;
	char tmp_opt[32], tmp_val[128];

	/* set defaults */
	*cmtu = C_DEFAULT_MTU;
	oto->interface[0] = '\0';
	cfg_guess_interface(oto->interface);
	strncpy(oto->prefix, C_DEFAULT_PREFIX, sizeof(oto->prefix));
	oto->ipv4_address[0] = '\0';

	f = fopen(config_file, "r");

	if (f == NULL) {
		log_warn("Configuration file %s doesn't exist, using defaults",
			 config_file);

		if (init) {
			log_error("IPv4 address unconfigured! Exiting");
			exit(1);
		}

		return 0;
	}

	while (c = getc(f), !feof(f)) {
		ln++;

		/* comments */
		if (c == '#') {
			/* skip this line */
			while (c = getc(f), c != '\n' && !feof(f));

			continue;
		}

		/* empty lines */
		if (c == '\n') {
			continue;
		}

		/* option is only of small letters */
		if (c < 'a' || c > 'z') {
			SYNTAX_ERROR(config_file, ln, 0, init);
		}

		/* read option */
		for (opt_len = 0; c != ' ' && c != '\t'; opt_len++,
		    c = getc(f)) {
			if (feof(f) || !((c >= 'a' && c <= 'z') || c == '_' ||
			    (c >= '0' && c <= '9'))) {
				SYNTAX_ERROR(config_file, ln, opt_len, init);
			}

			if (opt_len < 32 - 1) {
				tmp_opt[opt_len] = c;
			} else {
				SYNTAX_ERROR(config_file, ln, opt_len, init);
			}
		}
		tmp_opt[opt_len] = '\0';

		/* skip white space */
		for (wht_len = 0; c == ' ' || c == '\t'; wht_len++,
		    c = getc(f)) {
			if (feof(f)) {
				SYNTAX_ERROR(config_file, ln, opt_len + wht_len,
					     init);
			}
		}

		/* read value */
		for (val_len = 0; c != ' ' && c != '\t' && c != '\n'; val_len++,
		    c = getc(f)) {
			if (feof(f)) {
				SYNTAX_ERROR(config_file, ln, opt_len, init);
			}

			if (val_len < 128 - 1) {
				tmp_val[val_len] = c;
			} else {
				SYNTAX_ERROR(config_file, ln, opt_len, init);
			}
		}
		tmp_val[val_len] = '\0';

		/* skip rest of this line */
		if (c != '\n') {
			while (c = getc(f), c != '\n' && !feof(f));
		}

		/* recognize the option */
		if (!strcmp(tmp_opt, "mtu")) {
			*cmtu = atoi(tmp_val);
			if (*cmtu > MAX_MTU) {
				log_warn("MTU setting is over maximum (%d), "
					 "falling to default value (%d)",
					 MAX_MTU, C_DEFAULT_MTU);
				*cmtu = C_DEFAULT_MTU;
			}
		} else if (!strcmp(tmp_opt, "interface")) {
			strncpy(oto->interface, tmp_val,
				sizeof(oto->interface));
		} else if (!strcmp(tmp_opt, "prefix")) {
			strncpy(oto->prefix, tmp_val, sizeof(oto->prefix));
		} else if (!strcmp(tmp_opt, "ipv4_address")) {
			if (val_len < sizeof(oto->ipv4_address)) {
				strncpy(oto->ipv4_address, tmp_val,
					sizeof(oto->ipv4_address));
			} else {
				SYNTAX_ERROR(config_file, ln, opt_len + wht_len,
					     init);
			}
		} else {
			log_error("Unknown configuration option");
			SYNTAX_ERROR(config_file, ln, 0, init);
		}
	}

	fclose(f);

	if (init && oto->ipv4_address[0] == '\0') {
		log_error("IPv4 address unconfigured! Exiting");
		exit(1);
	}

	return 0;
}

/**
 * Configures host IP addresses for usage in ICMP error messages. If some or
 * both is not available, defaults are used.
 *
 * As a default in case of IPv4 is used IPv4 address assigned to WrapSix in
 * configuration, in case of IPv6 is used made up address from default NAT64
 * prefix -- WrapSix itself cannot act as a host so it doesn't matter.
 *
 * @param	cinterface		Name of the interface WrapSix sits on
 * @param	ipv6_addr		Where to save host IPv6 address
 * @param	ipv4_addr		Where to save host IPv4 address
 * @param	default_ipv4_addr	IPv4 address assigned to WrapSix
 *
 * @return      0 for success
 * @return      1 for failure
 */
int cfg_host_ips(char *cinterface, struct s_ipv6_addr *ipv6_addr,
		 struct s_ipv4_addr *ipv4_addr, char *default_ipv4_addr)
{
	struct ifaddrs *ifaddr, *ifa;
	/* 0x01 IPv6 from WrapSix' interface
	 * 0x02 IPv4 from WrapSix' interface
	 * 0x04 IPv6 from another interface
	 * 0x08 IPv4 from another interface
	 */
	char found = 0;
	char ip_text[40];

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return 1;
	}

	/* Walk through linked list, maintaining head pointer so we can free
	 * list later */

	/* first try to get addresses from the interface */
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		if (!strcmp(ifa->ifa_name, cinterface)) {
			if (ifa->ifa_addr->sa_family == AF_INET6 &&
			    !(found & 0x01)) {
				found |= 0x01;
				getnameinfo(ifa->ifa_addr,
					    sizeof(struct sockaddr_in6),
					    ip_text, sizeof(ip_text), NULL, 0,
					    NI_NUMERICHOST);
				inet_pton(AF_INET6, ip_text, ipv6_addr);
			} else if (ifa->ifa_addr->sa_family == AF_INET &&
				   !(found & 0x02)) {
				found |= 0x02;
				getnameinfo(ifa->ifa_addr,
					    sizeof(struct sockaddr_in),
					    ip_text, sizeof(ip_text), NULL, 0,
					    NI_NUMERICHOST);
				inet_pton(AF_INET, ip_text, ipv4_addr);
			}
		} else {	/* look for addresses on other interfaces too */
			if (ifa->ifa_addr->sa_family == AF_INET6 &&
			    !(found & 0x05)) {
				found |= 0x04;
				getnameinfo(ifa->ifa_addr,
					    sizeof(struct sockaddr_in6),
					    ip_text, sizeof(ip_text), NULL, 0,
					    NI_NUMERICHOST);
				inet_pton(AF_INET6, ip_text, ipv6_addr);
			} else if (ifa->ifa_addr->sa_family == AF_INET &&
				   !(found & 0x0a)) {
				found |= 0x08;
				getnameinfo(ifa->ifa_addr,
					    sizeof(struct sockaddr_in),
					    ip_text, sizeof(ip_text), NULL, 0,
					    NI_NUMERICHOST);
				inet_pton(AF_INET, ip_text, ipv4_addr);
			}
		}

		if ((found & 0x03) == 0x03) {
			break;
		}
	}

	/* no IPv4 address -> use default */
	if (!(found & 0x0a)) {
		inet_pton(AF_INET, default_ipv4_addr, ipv4_addr);
	}

	/* IPv6 default? huh... but we can't work without host IPv6 address */
	if (!(found & 0x05)) {
		/* FUN: try to decode it ;c) */
		inet_pton(AF_INET6, "64:ff9b::E7ad:514", ipv6_addr);
	}

	freeifaddrs(ifaddr);

	return 0;
}

/**
 * Gets name of first non-loopback network interface.
 *
 * @param	cinterface	Where to save the interface name
 */
void cfg_guess_interface(char *cinterface)
{
	struct ifaddrs *ifaddr, *ifa;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return;
	}

	/* Walk through linked list, maintaining head pointer so we can free
	 * list later */

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		/* skip loopback */
		if (strcmp(ifa->ifa_name, "lo")) {
			strncpy(cinterface, ifa->ifa_name,
				sizeof(((struct s_cfg_opts *) NULL)->interface)
			);
			break;
		}
	}

	freeifaddrs(ifaddr);
}
