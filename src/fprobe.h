/*
	Copyright (C) Slava Astashonok <sla@0n.ru>

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License.

	$Id: fprobe.h,v 1.3.2.6 2005/01/29 19:28:04 sla Exp $
*/

#ifndef _FPROBE_H_
#define _FPROBE_H_

#include <my_inttypes.h>
#include "netflow.h"

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif

#define SCHED SCHED_FIFO
#define EMIT_TIMEOUT 5
#define UNPENDING_TIMEOUT 5
#define THREADS 5
#define COPY_INTO 0
#define MOVE_INTO 1

#define NF_INFO_ARRAY 1
struct DLT {
	int linktype;
	unsigned offset_link;
	unsigned offset_nl;
	unsigned offset_nl_nosnap;
	char *descr;
};

struct Time {
	time_t sec;
	long usec;
};

struct Flow {
	/* ip src address */
	struct in_addr sip;
	/* ip dst address */
	struct in_addr dip;
	/* ip protocol */
	uint8_t proto;
	/* ip fragment id */
	uint16_t id;
	/* tcp/udp src port or icmp message type */
	uint16_t sp;
	/* tcp/udp dst port or icmp type sub-code */
	uint16_t dp;
	/* ip ToS */
	uint8_t tos;
	/* tcp flags */
	uint8_t tcp_flags;
	/* tcp first_ack number */
	uint32_t first_ack;
	/* tcp last ack number */
	uint32_t last_ack;
	/* number of packets */
	unsigned long pkts;
	/* sum of packets sizes */
	unsigned long size;
	/* fragment data size (for fragmented packets) */
	unsigned long sizeF;
	/* whole packet data size (for fragmented packets) */
	unsigned long sizeP;
	/* time of creation/flushing this flow */
	struct Time ctime;
	/* time of last modification this flow */
	struct Time mtime;
#define FLOW_FRAG	0x0001
#define FLOW_FRAGMASK	0x0003
#define FLOW_TL		0x0004
#define FLOW_LASTFRAG	0x0008
#define FLOW_PENDING	0x8000
	int flags;
#define HTTP_SYN    0x0001
#define HTTP_ACK    0x0002
#define HTTP_HAVE_GET    0x0004
#define HTTP_HAVE_OK    0x0008
#define HTTP_NOTCARE    0x0080
	uint16_t http_status;
	uint16_t info_ok;


#if NF_INFO_ARRAY
	uint8_t phost[NETFLOW_HTTP_HOST_SIZE];
	uint8_t puri[NETFLOW_HTTP_URI_SIZE];
	uint8_t preferer[NETFLOW_HTTP_REFERER_SIZE];
#else
	uint8_t *phost;
	uint8_t *puri;
	uint8_t *preferer;
#endif
	struct Flow *next;
};

struct Flow_F {
	/* ip src address */
	struct in_addr sip;
	/* ip dst address */
	struct in_addr dip;
	/* ip protocol */
	uint8_t proto;
	/* ip fragment id */
	uint16_t id;
};

struct Flow_TL {
	/* ip src address */
	struct in_addr sip;
	/* ip dst address */
	struct in_addr dip;
	/* ip protocol */
	uint8_t proto;
	/* ip fragment id */
	uint16_t id;
	/* tcp/udp src port or icmp message type */
	uint16_t sp;
	/* tcp/udp dst port or icmp type sub-code */
	uint16_t dp;
};

#define SIGALRM_MASK 1
#define SIGTERM_MASK 2
#define SIGUSR1_MASK 4

struct peer {
	int sock;
	struct sockaddr_in addr;
	struct sockaddr_in laddr;
	int type;
	uint32_t seq;
};

#define PEER_MIRROR 0
#define PEER_ROTATE 1

#endif
