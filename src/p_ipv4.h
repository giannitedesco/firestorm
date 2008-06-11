/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _P_IPV4_HEADER_INCLUDED_
#define _P_IPV4_HEADER_INCLUDED_

struct ipfrag_dcb {
	struct _dcb ip_dcb;
	const struct pkt_iphdr *ip_iph;
};

struct ip_dcb {
	struct _dcb ip_dcb;
	const struct pkt_iphdr *ip_iph;
	const struct pkt_ahhdr *ip_ah;
};

struct tcp_dcb {
	struct _dcb tcp_dcb;
	const struct pkt_iphdr *tcp_iph;
	const struct pkt_ahhdr *tcp_ah;
	const struct pkt_tcphdr *tcp_hdr;
	struct tcp_session *tcp_sess;
};

struct udp_dcb {
	struct _dcb udp_dcb;
	const struct pkt_iphdr *udp_iph;
	const struct pkt_ahhdr *udp_ah;
	const struct pkt_udphdr *udp_hdr;
};

struct icmp_dcb {
	struct _dcb icmp_dcb;
	const struct pkt_iphdr *icmp_iph;
	const struct pkt_ahhdr *icmp_ah;
	const struct pkt_icmphdr *icmp_hdr;
};

/* Keeps each individual fragment */
struct ipfrag {
	struct ipfrag		*next;
	int			len;
	int			offset;
	void			*data;
	unsigned int		free;
	void			*fdata; /* Data to free */
	unsigned int		flen;
};

/* This is an IP session structure */
struct ipq {
	struct ipq *next;
	struct ipq **pprev;
	struct ipq *next_time;
	struct ipq *prev_time;
	
	/* Identify the packet */
	uint32_t saddr;
	uint32_t daddr;
	uint16_t id;
	uint8_t protocol;

#define FIRST_IN 0x2
#define LAST_IN 0x1
	uint8_t last_in;

	/* Linked list of fragments */
	struct ipfrag *fragments;

	/* Total size of all the fragments we have */
	int meat;

	/* Total length of full packet */
	int len;

	/* Stuff we need for reassembly */
	timestamp_t	time;
};

/* A simplex tcp stream */
struct tcp_stream {
	uint8_t		state; /* from above enum */
#define TF_SACK_OK	(1<<0)
#define TF_WSCALE_OK	(1<<1)
#define TF_TSTAMP_OK	(1<<2)
	uint8_t		flags; /* optional features */
	uint8_t		scale; /* scaling factor */
	uint8_t		queue; /* in queue mode */

	uint32_t	ts_recent; /* a recent timestamp */
	uint32_t	ts_recent_stamp; /* local time on it */

	uint32_t	snd_una; /* first byte we want ack for */
	uint32_t	snd_nxt; /* next sequence to send */

	uint32_t	rcv_nxt; /* what we want to recv next */
	uint32_t	rcv_wnd; /* receiver window */
	uint32_t	rcv_wup; /* rcv_nxt on last window update */

	uint32_t	isn; /* equivalent of rfc793 iss */
};

/* Reassembly buffer */
struct tcp_sbuf {
	struct tcpr_node *root; /* root node of rbtree */
	uint32_t begin; /* sequence number of first byte (not always rcv_nxt) */
	uint32_t reasm_begin; /* sequence number of first unswallowed byte */
};

/* A duplex tcp session */
struct tcp_session {
	/* Global LRU list */
	struct list_head lru;

	/* Timeout list, for SYN timeouts etc.. */
	struct list_head tmo;

	/* Hash table collision chaining */
	struct tcp_session **hash_pprev, *hash_next;

	/* TCP state: network byte order */
	uint32_t c_addr, s_addr;
	uint16_t c_port, s_port;

	/* TCP state: host byte order */
	struct tcp_stream client;
	struct tcp_stream server;

	struct tcp_sbuf c_reasm;
	struct tcp_sbuf s_reasm;

	/* Application layer protocol carried on this stream */
	struct _proto *proto;

	/* Application layer state (flow information) */
	void *flow;

	/* expiry time */
	timestamp_t expire;
};

/* tcp_session allocator union */
union tcp_union {
	union tcp_union *next;
	struct tcp_session s;
};

/* sizeof("255.255.255.255\0") */
#define IPSTR_SZ 16
typedef char ipstr_t[IPSTR_SZ];
void iptostr(ipstr_t str, uint32_t ip);

extern struct _decoder _ipv4_decoder;
extern struct _flow_tracker _ipv4_ipdefrag;
extern struct _flow_tracker _ipv4_tcpflow;

uint16_t _ip_csum(const struct pkt_iphdr *iph);

#endif /* _P_IPV4_HEADER_INCLUDED_ */
