/*
 *  WrapSix
 *  Copyright (C) 2008-2013  xHire <xhire@wrapsix.org>
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

#include <stdlib.h>		/* malloc */
#include <time.h>		/* time */

#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "log.h"
#include "nat.h"
#include "radixtree.h"
#include "wrapper.h"

struct s_radixtree_nat6 {
	struct s_ipv6_addr	ipv6;
	struct s_ipv4_addr	ipv4;
	unsigned short		port_src;
	unsigned short		port_dst;
} __attribute__ ((__packed__));

struct s_radixtree_nat4 {
	struct s_ipv4_addr	addr;
	unsigned short		port_src;
	unsigned short		port_dst;
	unsigned char		zeros;		/* unused space */
} __attribute__ ((__packed__));

struct s_radixtree_fragments4 {
	struct s_ipv4_addr	addr;
	unsigned short		id;
} __attribute__ ((__packed__));

radixtree_t *nat6_tcp, *nat6_udp, *nat6_icmp,
	    *nat4_tcp, *nat4_udp, *nat4_icmp,
	    *nat4_tcp_fragments;

/* Linked lists for handling timeouts of connections */
linkedlist_t *timeout_icmp, *timeout_udp,
	     *timeout_tcp_est, *timeout_tcp_trans,
	     *timeout_tcp_fragments;

/* Declarations */
void nat_delete_connection(radixtree_t *nat_proto4, radixtree_t *nat_proto6,
                           struct s_nat *connection);

/**
 * Initialization of NAT tables.
 */
void nat_init(void)
{
	nat6_tcp  = radixtree_create();
	nat6_udp  = radixtree_create();
	nat6_icmp = radixtree_create();

	nat4_tcp  = radixtree_create();
	nat4_udp  = radixtree_create();
	nat4_icmp = radixtree_create();

	nat4_tcp_fragments = radixtree_create();

	timeout_icmp	  = linkedlist_create();
	timeout_udp	  = linkedlist_create();
	timeout_tcp_est	  = linkedlist_create();
	timeout_tcp_trans = linkedlist_create();
	timeout_tcp_fragments = linkedlist_create();
}

/**
 * Clean-up of NAT tables.
 */
void nat_quit(void)
{
	/* 128 + 16 + 32 + 16 = 192 / 6 = 32 */
	radixtree_destroy(nat6_tcp,  32);
	radixtree_destroy(nat6_udp,  32);
	radixtree_destroy(nat6_icmp, 32);

	/* 32 + 16 + 16 + 8 = 72 / 6 = 12 */
	radixtree_destroy(nat4_tcp,  12);
	radixtree_destroy(nat4_udp,  12);
	radixtree_destroy(nat4_icmp, 12);

	/* 32 + 16 = 48 / 6 = 8 */
	radixtree_destroy(nat4_tcp_fragments, 8);

	linkedlist_destroy(timeout_icmp);
	linkedlist_destroy(timeout_udp);
	linkedlist_destroy(timeout_tcp_est);
	linkedlist_destroy(timeout_tcp_trans);
	linkedlist_destroy(timeout_tcp_fragments);
}

/**
 * Lookup or create NAT connection for outgoing IPv6 packet.
 *
 * @param	nat_proto6	IPv6 NAT table
 * @param	nat_proto4	IPv4 NAT table
 * @param	eth_src		Source MAC address
 * @param	ipv6_src	Source IPv6 address
 * @param	ipv6_dst	Destination IPv6 address
 * @param	port_src	Source port
 * @param	port_dst	Destination port
 * @param	create		Whether or not to create new NAT entry
 *
 * @return	NULL when it wasn't possible to create connection
 * @return	pointer to connection structure otherwise
 */
struct s_nat *nat_out(radixtree_t *nat_proto6, radixtree_t *nat_proto4,
		      struct s_mac_addr eth_src,
		      struct s_ipv6_addr ipv6_src, struct s_ipv6_addr ipv6_dst,
		      unsigned short	 port_src, unsigned short     port_dst,
		      unsigned char create)
{
	struct s_nat *result, *connection;

	struct s_radixtree_nat4 radixsearch4;
	struct s_radixtree_nat6 radixsearch6;

	/* create structure to search in the tree */
	radixsearch6.ipv6 = ipv6_src;
	ipv6_to_ipv4(&ipv6_dst, &radixsearch6.ipv4);
	radixsearch6.port_src = port_src;
	radixsearch6.port_dst = port_dst;

	if ((result = (struct s_nat *) radixtree_lookup(nat_proto6,
	    radixtree_chunker, &radixsearch6, sizeof(radixsearch6))) == NULL) {
		if (create > 0) {
			/* if no connection is found, let's create one */
			if ((connection =
			     (struct s_nat *) malloc(sizeof(struct s_nat))) ==
			    NULL) {
				log_error("Lack of free memory");
				return NULL;
			}

			connection->mac = eth_src;
			connection->ipv6 = ipv6_src;
			connection->ipv4 = radixsearch6.ipv4;
			connection->ipv6_port_src = port_src;
			connection->ipv4_port_dst = port_dst;
			connection->state = 1;
			connection->llnode = NULL;

			radixsearch4.addr = radixsearch6.ipv4;
			radixsearch4.port_src = port_dst;
			radixsearch4.zeros = 0x0;

			/* generate some outgoing port */
			do {
				/* returns port from range 1024 - 65535 */
				radixsearch4.port_dst = (rand() % 64511) + 1024;

				result = radixtree_lookup(nat_proto4,
							  radixtree_chunker,
							  &radixsearch4,
							  sizeof(radixsearch4));
			} while (result != NULL);

			connection->ipv4_port_src = radixsearch4.port_dst;

			/* save this connection to the NAT table (to *both* of
			 * them) */
			radixtree_insert(nat_proto6, radixtree_chunker,
					 &radixsearch6, sizeof(radixsearch6),
					 connection);
			radixtree_insert(nat_proto4, radixtree_chunker,
					 &radixsearch4, sizeof(radixsearch4),
					 connection);

			return connection;
		} else {
			return NULL;
		}
	} else {
		/* when connection is found, return it */
		return result;
	}
}

/**
 * Lookup NAT connection for incoming IPv4 packet.
 *
 * @param	nat_proto4	NAT table
 * @param	ipv4_src	Source IPv4 address
 * @param	port_src	Source port
 * @param	port_dst	Destination port
 *
 * @return	NULL when no connection was found
 * @return	pointer to connection structure otherwise
 */
struct s_nat *nat_in(radixtree_t *nat_proto4, struct s_ipv4_addr ipv4_src,
		     unsigned short port_src, unsigned short port_dst)
{
	struct s_nat *result;

	/* create structure to search in the tree */
	struct s_radixtree_nat4 radixsearch4;
	radixsearch4.addr = ipv4_src;
	radixsearch4.port_src = port_src;
	radixsearch4.port_dst = port_dst;
	radixsearch4.zeros = 0x0;

	if ((result = (struct s_nat *) radixtree_lookup(nat_proto4,
	     radixtree_chunker, &radixsearch4, sizeof(radixsearch4))) == NULL) {
		/* when connection is not found, drop the packet */
		return NULL;
	} else {
		/* when connection is found, return it */
		return result;
	}
}

/**
 * Retrieve or create data structure via fragment identification.
 *
 * @param	nat_proto4	Radix tree of fragments
 * @param	nat_timeout	Linked list in which to watch for timeout
 * @param	ipv4_src	Source IPv4 address
 * @param	id		Fragment identification
 *
 * @return	Structure for fragments (either retrieved or created)
 * @return	NULL when structure for fragments couldn't be created
 */
struct s_nat_fragments *nat_in_fragments(radixtree_t *nat_proto4,
					 linkedlist_t *nat_timeout,
					 struct s_ipv4_addr ipv4_src,
					 unsigned short id)
{
	struct s_nat_fragments *result;

	/* create structure to search in the tree */
	struct s_radixtree_fragments4 radixsearch4;
	radixsearch4.addr = ipv4_src;
	radixsearch4.id = id;

	if ((result = radixtree_lookup(nat_proto4, radixtree_chunker,
	     &radixsearch4, sizeof(radixsearch4))) != NULL) {
		return result;
	} else {
		/* when fragmentation is not found, add one */
		if ((result = (struct s_nat_fragments *)
		     malloc(sizeof(struct s_nat_fragments))) == NULL) {
			log_error("Lack of free memory");
			return NULL;
		}

		result->id = id;
		result->connection = NULL;
		result->queue = NULL;

		radixtree_insert(nat_proto4, radixtree_chunker,
				 &radixsearch4, sizeof(radixsearch4),
				 result);
		linkedlist_append(nat_timeout, result);

		return result;
	}
}

/**
 * Remove one entry from "fragment NAT".
 *
 * @param	nat_proto4	Radix tree of fragments
 * @param	ipv4_src	Source IPv4 address
 * @param	id		Fragment identification
 */
void nat_in_fragments_cleanup(radixtree_t *nat_proto4,
			      struct s_ipv4_addr ipv4_src, unsigned short id)
{
	/* create structure to search in the tree */
	struct s_radixtree_fragments4 radixsearch4;
	radixsearch4.addr = ipv4_src;
	radixsearch4.id = id;

	if (radixtree_lookup(nat_proto4, radixtree_chunker, &radixsearch4,
	    sizeof(radixsearch4)) != NULL) {
		radixtree_delete(nat_proto4, radixtree_chunker, &radixsearch4,
				 sizeof(radixsearch4));
	}
}

/**
 * Delete a NAT connection.
 *
 * @param	nat_proto4	Relevant NAT4 table
 * @param	nat_proto6	Relevant NAT6 table
 * @param	connection	Connection to be deleted
 */
void nat_delete_connection(radixtree_t *nat_proto4, radixtree_t *nat_proto6,
                           struct s_nat *connection)
{
        /* create structure to search in the tree */
        struct s_radixtree_nat4 radixsearch4;
        struct s_radixtree_nat6 radixsearch6;

        radixsearch6.ipv6 = connection->ipv6;
        radixsearch6.ipv4 = connection->ipv4;
        radixsearch6.port_src = connection->ipv6_port_src;
        radixsearch6.port_dst = connection->ipv4_port_dst;

        radixsearch4.addr = connection->ipv4;
        radixsearch4.port_src = connection->ipv4_port_dst;
        radixsearch4.port_dst = connection->ipv4_port_src;
        radixsearch4.zeros = 0x0;

        if (radixtree_lookup(nat_proto4, radixtree_chunker, &radixsearch4,
            sizeof(radixsearch4)) != NULL) {
                radixtree_delete(nat_proto4, radixtree_chunker, &radixsearch4,
                                 sizeof(radixsearch4));
        }

        if (radixtree_lookup(nat_proto6, radixtree_chunker, &radixsearch6,
            sizeof(radixsearch6)) != NULL) {
                radixtree_delete(nat_proto6, radixtree_chunker, &radixsearch6,
                                 sizeof(radixsearch6));
        }

	free(connection);
	connection = NULL;
}

/**
 * Remove expired connections from NAT.
 */
void nat_cleaning(void)
{
	linkedlist_node_t *tmp;
	time_t curtime = time(NULL);

	/* TCP FRAGMENTS	[2 secs] */
	tmp = timeout_tcp_fragments->first.next;
	while (tmp->next != NULL && curtime - tmp->time >= 2) {
		tmp = tmp->next;

		/* destroy queue */
		linkedlist_destroy(((struct s_nat_fragments *)
				    tmp->prev->data)->queue);

		/* remove connection */
		nat_in_fragments_cleanup(nat4_tcp_fragments,
					 ((struct s_nat_fragments *)
					  tmp->prev->data)->connection->ipv4,
					 ((struct s_nat_fragments *)
					  tmp->prev->data)->id);

		free(((struct s_nat_fragments *) tmp->prev->data)->connection);
		free(tmp->prev->data);

		linkedlist_delete(timeout_tcp_fragments, tmp->prev);
	}

	/* ICMP		[60 secs] */
	tmp = timeout_icmp->first.next;
	while (tmp->next != NULL && curtime - tmp->time >= 60) {
		tmp = tmp->next;
		nat_delete_connection(nat4_icmp, nat6_icmp, tmp->prev->data);
		linkedlist_delete(timeout_icmp, tmp->prev);
	}

	/* TCP -- TRANS	[4 mins] */
	tmp = timeout_tcp_trans->first.next;
	while (tmp->next != NULL && curtime - tmp->time >= 4 * 60) {
		tmp = tmp->next;
		nat_delete_connection(nat4_tcp, nat6_tcp, tmp->prev->data);
		linkedlist_delete(timeout_tcp_trans, tmp->prev);
	}

	/* UDP		[5 mins (minimum is 2 mins)] */
	tmp = timeout_udp->first.next;
	while (tmp->next != NULL && curtime - tmp->time >= 5 * 60) {
		tmp = tmp->next;
		nat_delete_connection(nat4_udp, nat6_udp, tmp->prev->data);
		linkedlist_delete(timeout_udp, tmp->prev);
	}

	/* TCP -- EST	[2 hrs and 4 mins] */
	tmp = timeout_tcp_est->first.next;
	while (tmp->next != NULL && curtime - tmp->time >= 124 * 60) {
		tmp = tmp->next;
		nat_delete_connection(nat4_tcp, nat6_tcp, tmp->prev->data);
		linkedlist_delete(timeout_tcp_est, tmp->prev);
	}
}
