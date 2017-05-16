/*
 *  WrapSix
 *  Copyright (C) 2008-2010  xHire <xhire@wrapsix.org>
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

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>		/* inet_pton */
#include <unistd.h>		/* close */
#include <string.h>		/* memcpy */
#include <stdlib.h>		/* malloc */

struct s_dns_header {
	unsigned short	id;		/* 16 b; identifier of a request */
	unsigned short	flags;		/* 16 b */
	unsigned short	question;	/* 16 b; num of data in question sec */
	unsigned short	answer;		/* 16 b; num of RRs in answer sec */
	unsigned short	auth;		/* 16 b; num of RRs in authority sec */
	unsigned short	add;		/* 16 b; num of RRs in additional sec */
} __attribute__ ((__packed__));

struct s_dns_answer {
	char		*fqdn;		/* domain name of the record */
	unsigned short	dnlength;	/* length of the domain name */
	unsigned short	type;		/* 16 b; RR type code */
	unsigned short	class;		/* 16 b; class of the data in rdata */
	unsigned int	ttl;		/* 32 b; RR caching interval */
	unsigned short	rdlength;	/* 16 b; length of the rdata section */
	char		*rdata;		/* describes the resource */
} __attribute__ ((__packed__));

#define BUFFER_SIZE	512		/* maximum of a DNS packet */
#define IP		"::2"
#define RESOLVER	"::1"
#define PORT		53
#define PREFIX		"::"

unsigned short id = 0;

int resolver_connect(int *sock, struct sockaddr_in6 *sock_addr);
int udp_receive(int *sock, struct sockaddr_in6 *sock_addr, char *buffer, int *length);
int udp_send(int *sock, struct sockaddr_in6 *sock_addr, char *data, int length);
int lookup(unsigned short qtype, char *data, struct s_dns_answer **answer, unsigned short *answer_count);
int get_fqdn(char *fqdn, char *data, unsigned short *length);

int resolver_connect(int *sock, struct sockaddr_in6 *sock_addr)
{
	int tmp_sock;
	struct sockaddr_in6 tmp_sock_addr;
	char resolver[] = RESOLVER;

	/* create a socket */
	if ((tmp_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		fprintf(stderr, "[Error] Unable to create UDP socket for outgoing connections\n");
		return 1;
	}

	/* setup the socket */
	tmp_sock_addr.sin6_family = AF_INET6;
	tmp_sock_addr.sin6_port = htons(PORT);
	inet_pton(AF_INET6, (char *) &resolver, &(tmp_sock_addr.sin6_addr));

	/* return correct data */
	memcpy(sock, &tmp_sock, sizeof(int));
	memcpy(sock_addr, &tmp_sock_addr, sizeof(struct sockaddr_in6));

	return 0;
}

int udp_receive(int *sock, struct sockaddr_in6 *sock_addr, char *buffer, int *length)
{
	int tmp_length;
	int addrlen;

	addrlen = sizeof(struct sockaddr_in6);
	if ((tmp_length = recvfrom(*sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *) sock_addr, (socklen_t *) &addrlen)) == -1) {
		char str_ip[128];
		inet_ntop(AF_INET6, &(sock_addr->sin6_addr), (char *) &str_ip, 128);

		fprintf(stderr, "[Error] Unable to read from UDP socket [%s]:%d\n", str_ip, PORT);

		return 1;
	}

	memcpy(length, &tmp_length, sizeof(int));

	return 0;
}

int udp_send(int *sock, struct sockaddr_in6 *sock_addr, char *data, int length)
{
	int addrlen;

	addrlen = sizeof(struct sockaddr_in6);
	if (sendto(*sock, data, length, 0, (struct sockaddr *) sock_addr, addrlen) != length) {
		char str_ip[128];
		inet_ntop(AF_INET6, &(sock_addr->sin6_addr), (char *) &str_ip, 128);

		fprintf(stderr, "[Error] Unable to write to UDP socket [%s]:%d\n", str_ip, PORT);
		return 1;
	}

	return 0;
}

int lookup(unsigned short qtype, char *data, struct s_dns_answer **answer, unsigned short *answer_count)
{
	int i, j;
	unsigned short length;
	unsigned short qclass;

	int resolver_sock;
	struct sockaddr_in6 resolver_sock_addr;

	char buffer[BUFFER_SIZE];
	struct s_dns_header *header;
	struct s_dns_answer *answers;

	header = (struct s_dns_header *) &buffer;

	/* create the request */
	header->id		= htons(++id);
	header->flags		= htons(0x0100);	/* recursion desired */
	header->question	= htons(1);
	header->answer		= 0;
	header->auth		= 0;
	header->add		= 0;

	/* copy the fqdn from 'data' */
	for (i = sizeof(struct s_dns_header), length = i, j = 0;; i++, j++) {
		buffer[i] = data[j];

		if (length == i) {
			length += buffer[i] + 1;

			if (buffer[i] == 0x0) {
				break;
			}
		}
	}

	/* set the rest fields of the question section */
	qtype = htons(qtype);
	qclass = htons(0x1);
	memcpy(&buffer[i + 1], &qtype, 2);
	memcpy(&buffer[i + 3], &qclass, 2);

	/* create a connection socket */
	resolver_connect(&resolver_sock, &resolver_sock_addr);

	/* send the request */
	udp_send(&resolver_sock, &resolver_sock_addr, (char *) &buffer, i + 5);

	/* fetch the answer */
	udp_receive(&resolver_sock, &resolver_sock_addr, (char *) &buffer, (int *) &length);

	/* close the socket */
	close(resolver_sock);

	/* process the answer */
	header = (struct s_dns_header *) &buffer;
	header->answer = htons(header->answer);
	if (htons(header->id) == id && header->answer > 0) {
		if ((answers = (struct s_dns_answer *) malloc(header->answer * sizeof(struct s_dns_answer))) == NULL) {
			fprintf(stderr, "[Error] Lack of free memory\n");
			return 1;
		}

		/* save the count of the answers */
		memcpy(answer_count, &header->answer, sizeof(unsigned short));

		/* first go over the question section */
		j = sizeof(struct s_dns_header);
		if (htons(header->question) > 0) {
			while (buffer[j] != 0x0) {
				j += buffer[j] + 1;
			}

			/* set the position of answer section */
			j += 5;
		}

		/* go through all answers and process them */
		for (i = 0; i < header->answer; i++) {
			/* is the answer compressed? save the fqdn in both cases */
			if (buffer[j] & 0xc0) {
				get_fqdn((char *) &(answers[i].fqdn), &buffer[(int) buffer[j + 1]], &(answers[i].dnlength));
				j += 2;
			} else {
				get_fqdn((char *) &(answers[i].fqdn), &buffer[j], &(answers[i].dnlength));
				j += answers[i].dnlength;
			}

			/* save the rest of the answer */
			memcpy(&(answers[i].type), &buffer[j], 2);
			memcpy(&(answers[i].class), &buffer[j + 2], 2);
			memcpy(&(answers[i].ttl), &buffer[j + 4], 4);
			memcpy(&(answers[i].rdlength), &buffer[j + 8], 2);
			answers[i].rdlength = htons(answers[i].rdlength);

			if ((answers[i].rdata = (char *) malloc(answers[i].rdlength)) == NULL) {
				fprintf(stderr, "[Error] Lack of free memory\n");
				return 1;
			}

			memcpy(answers[i].rdata, &buffer[j + 10], answers[i].rdlength);

			j += 10 + answers[i].rdlength;
		}

		/* return address of array of answers */
		memcpy(answer, &answers, sizeof(struct s_dns_answer *));
	} else {
		return 1;
	}

	return 0;
}

int get_fqdn(char *fqdn, char *data, unsigned short *length)
{
	unsigned short i, offset;
	char buffer[BUFFER_SIZE];
	char *tmp;

	offset = 0;

	/* read the fqdn and save it into the buffer */
	for (i = 0; data[i] != 0x0; i++) {
		buffer[i] = data[i];

		if (i == offset) {
			offset += data[i] + 1;
		}
	}

	/* don't forget to add the ending octet */
	buffer[offset] = 0x0;
	offset++;

	/* create a storage to save the fqdn */
	if ((tmp = (char *) malloc(offset)) == NULL) {
		fprintf(stderr, "[Error] Lack of free memory\n");
		return 1;
	}

	/* save length of the fqdn */
	memcpy(length, &offset, sizeof(unsigned short));

	/* save the fqdn */
	memcpy(tmp, &buffer, *length);

	/* save the address of the storage of the fqdn */
	memcpy(fqdn, &tmp, sizeof(char *));

	return 0;
}

int main(int argc, char **argv)
{
	int i, j;
	int length, offset;
	unsigned short k;
	unsigned short answer_count;

	char ip[] = IP;
	char buffer[BUFFER_SIZE];
	char buffer_answer[BUFFER_SIZE];

	int sock;
	struct sockaddr_in6 sock_addr,
			    client_sock_addr;

	int resolver_sock;
	struct sockaddr_in6 resolver_sock_addr;

	struct s_dns_header *dns, *dns_answer;
	unsigned short qtype, qclass;
	struct s_dns_answer *answers;

	struct in6_addr ipv6_prefix;

	/* initialization */
	inet_pton(AF_INET6, PREFIX, &ipv6_prefix);

	/* create the socket */
	if ((sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		fprintf(stderr, "[Error] Unable to create UDP socket\n");
		return 1;
	}

	/* setup the socket */
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = htons(PORT);
	inet_pton(AF_INET6, (char *) &ip, &(sock_addr.sin6_addr));

	/* bind the socket to address and port */
	if (bind(sock, (struct sockaddr *) &(sock_addr), sizeof(sock_addr)) == -1) {
		fprintf(stderr, "[Error] Unable to bind UDP socket to %s:%d\n", IP, PORT);
		return 1;
	}

	for (;;) {
		/* fetch a request */
		udp_receive(&sock, &client_sock_addr, (char *) &buffer, &length);

		/* process the request */
		dns = (struct s_dns_header *) &buffer;
		/* TODO: there could be more than one question */
		offset = sizeof(struct s_dns_header);
		while (buffer[offset] != 0x0) {
			offset += buffer[offset] + 1;
		}
		memcpy(&qtype, &buffer[offset + 1], 2);
		memcpy(&qclass, &buffer[offset + 3], 2);
		qtype = htons(qtype);
		qclass = htons(qclass);

		/* this is AAAA request */
		if (qclass == 0x1 && qtype == 0x1c) {
			answers = NULL;
			/* first look up if some AAAA exists */
			if (lookup(0x1c, &buffer[sizeof(struct s_dns_header)], &answers, &answer_count) == 0) {
				/* send back an answer */
				dns_answer = (struct s_dns_header *) &buffer_answer;
				dns_answer->id		= dns->id;
				dns_answer->flags	= htons(0x8180);
				dns_answer->question	= htons(1);
				dns_answer->answer	= htons(answer_count);
				dns_answer->auth	= 0;
				dns_answer->add		= 0;

				/* copy question section */
				i = offset - sizeof(struct s_dns_header) + 5;
				memcpy(&buffer_answer[sizeof(struct s_dns_header)], &buffer[sizeof(struct s_dns_header)], i);

				/* construct answer section */
				i = offset + 5;
				for (j = 0; j < answer_count; j++) {
					/* copy fqdn */
					memcpy(&buffer_answer[i], answers[j].fqdn, answers[j].dnlength);
					i += answers[j].dnlength;

					/* copy type, class and ttl */
					memcpy(&buffer_answer[i], &(answers[j].type), 2 * sizeof(unsigned short) + sizeof(unsigned int));
					i += 2 * sizeof(unsigned short) + sizeof(unsigned int);

					/* copy rdlength */
					k = htons(answers[j].rdlength);
					memcpy(&buffer_answer[i], &k, sizeof(unsigned short));
					i += sizeof(unsigned short);

					/* copy rdata */
					memcpy(&buffer_answer[i], answers[j].rdata, answers[j].rdlength);
					i += answers[j].rdlength;

					/* memory clean-up */
					free(answers[j].fqdn);
					free(answers[j].rdata);
				}

				/* send it */
				udp_send(&sock, &client_sock_addr, (char *) &buffer_answer, i);

				/* memory clean-up */
				free(answers);
			/* second look up if some A exists & transform it */
			} else if (lookup(0x1, &buffer[sizeof(struct s_dns_header)], &answers, &answer_count) == 0) {
				/* send back an answer */
				dns_answer = (struct s_dns_header *) &buffer_answer;
				dns_answer->id		= dns->id;
				dns_answer->flags	= htons(0x8180);
				dns_answer->question	= htons(1);
				dns_answer->answer	= htons(answer_count);
				dns_answer->auth	= 0;
				dns_answer->add		= 0;

				/* copy question section */
				i = offset - sizeof(struct s_dns_header) + 5;
				memcpy(&buffer_answer[sizeof(struct s_dns_header)], &buffer[sizeof(struct s_dns_header)], i);

				/* construct answer section */
				i = offset + 5;
				for (j = 0; j < answer_count; j++) {
					/* copy fqdn */
					memcpy(&buffer_answer[i], answers[j].fqdn, answers[j].dnlength);
					i += answers[j].dnlength;

					/* set type */
					k = htons(0x1c);
					memcpy(&buffer_answer[i], &k, sizeof(unsigned short));
					i += sizeof(unsigned short);

					/* copy class and ttl */
					memcpy(&buffer_answer[i], &(answers[j].class), sizeof(unsigned short) + sizeof(unsigned int));
					i += sizeof(unsigned short) + sizeof(unsigned int);

					/* set rdlength */
					k = htons(sizeof(ipv6_prefix));
					memcpy(&buffer_answer[i], &k, sizeof(unsigned short));
					i += sizeof(unsigned short);

					/* copy IPv6 prefix */
					memcpy(&buffer_answer[i], &ipv6_prefix, sizeof(ipv6_prefix) - answers[j].rdlength);
					i += sizeof(ipv6_prefix) - answers[j].rdlength;

					/* copy IPv4 address */
					memcpy(&buffer_answer[i], answers[j].rdata, answers[j].rdlength);
					i += answers[j].rdlength;

					/* memory clean-up */
					free(answers[j].fqdn);
					free(answers[j].rdata);
				}

				/* send it */
				udp_send(&sock, &client_sock_addr, (char *) &buffer_answer, i);

				/* memory clean-up */
				free(answers);
			/* third say we have no clue about the fqdn */
			} else {
				/* send back an answer */
				dns_answer = (struct s_dns_header *) &buffer_answer;
				dns_answer->id		= dns->id;
				dns_answer->flags	= htons(0x8183);
				dns_answer->question	= htons(1);
				dns_answer->answer	= 0;
				dns_answer->auth	= 0;
				dns_answer->add		= 0;

				/* copy question section */
				i = offset - sizeof(struct s_dns_header) + 5;
				memcpy(&buffer_answer[sizeof(struct s_dns_header)], &buffer[sizeof(struct s_dns_header)], i);
				i += sizeof(struct s_dns_header);

				/* send it */
				udp_send(&sock, &client_sock_addr, (char *) &buffer_answer, i);
			}
		/* this is other than AAAA request -> just proxy it */
		} else {
			/* create a connection socket */
			resolver_connect(&resolver_sock, &resolver_sock_addr);

			/* send the request */
			udp_send(&resolver_sock, &resolver_sock_addr, (char *) &buffer, length);

			/* fetch the answer */
			udp_receive(&resolver_sock, &resolver_sock_addr, (char *) &buffer, (int *) &length);

			/* close the socket */
			close(resolver_sock);


			/* forward the answer to the client */
			udp_send(&sock, &client_sock_addr, (char *) &buffer, length);
		}
	}

	/* final clean-up */
	close(sock);

	return 0;
}
