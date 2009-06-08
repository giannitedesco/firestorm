/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _TCPIP_HEADER_INCLUDED_
#define _TCPIP_HEADER_INCLUDED_

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

struct tcp_server {
	struct tcp_server **hash_pprev, *hash_next;
	uint32_t addr;
	uint16_t port;
	uint16_t _pad0;
	unsigned int use;
	// struct _proto *proto;
};

/* A simplex tcp stream */
struct tcp_state {
#define TF_SACK_OK	(1<<0)
#define TF_WSCALE_OK	(1<<1)
#define TF_TSTAMP_OK	(1<<2)
	uint8_t		flags; /* optional features */
	uint8_t		scale; /* scaling factor */
	uint8_t		_pad0;
	uint8_t		_pad1;

	uint32_t	snd_una; /* first byte we want ack for */
	uint32_t	snd_nxt; /* next sequence to send */

	uint32_t	rcv_nxt; /* what we want to recv next */
	uint32_t	rcv_wnd; /* receiver window */
	uint32_t	rcv_wup; /* rcv_nxt on last window update */

	uint32_t	ts_recent; /* a recent timestamp */
	uint32_t	ts_recent_stamp; /* local time on it */
};

/* A duplex tcp session */
#define TCP_SESSION_S1	0
#define TCP_SESSION_S2	1
#define TCP_SESSION_S3	2
#define TCP_SESSION_E	3
#define TCP_SESSION_CF1	4
#define TCP_SESSION_CF2	5
#define TCP_SESSION_CF3	6
#define TCP_SESSION_SF1	7
#define TCP_SESSION_SF2	8
#define TCP_SESSION_SF3	9
#define TCP_SESSION_C	10

struct tcp_session {
	/* Timeout and LRU list */
	struct list_head lru;

	/* Hash table collision chaining */
	struct tcp_session **hash_pprev, *hash_next;

	/* TCP state: network byte order */
	uint32_t c_addr, s_addr;
	uint16_t c_port, s_port;

	uint16_t state;
	uint16_t _pad0;

	/* TCP state: host byte order */
	struct tcp_state c_wnd;
	struct tcp_state *s_wnd;

	/* Per-server data structure */
	struct tcp_server *server;

	/* expiry time */
	timestamp_t expire;
};

#define TCPHASH 509 /* prime */
struct tcpflow {
	/* flow hash */
	struct tcp_session *hash[TCPHASH];

	/* memory caches */
	obj_cache_t session_cache;
	obj_cache_t server_cache;
	obj_cache_t sstate_cache;

	/* timeout lists */
	struct list_head lru;
	struct list_head tmo_30;

	/* stats */
	unsigned int num_active;
	unsigned int max_active;
	unsigned int num_segments;

	unsigned int num_csum_errs;
	unsigned int num_ttl_errs;
};

#define IPHASH 127 /* Mersenne prime */
struct ipdefrag {
	struct ipq *ipq_latest;
	struct ipq *ipq_oldest;
	size_t mem;
	struct ipq *hash[IPHASH]; /* IP fragment hash table */
	obj_cache_t ipq_cache;
	obj_cache_t frag_cache;
};

struct ip_flow_state {
	struct tcpflow tcpflow;
	struct ipdefrag ipdefrag;
};

int _ipdefrag_ctor(struct ipdefrag *ipd);
void _ipdefrag_dtor(struct ipdefrag *ipd);
void _ipdefrag_track(flow_state_t s, pkt_t pkt, dcb_t dcb_ptr);

int _tcpflow_ctor(struct tcpflow *ipd);
void _tcpflow_dtor(struct tcpflow *ipd);
void _tcpflow_track(flow_state_t sptr, pkt_t pkt, dcb_t dcb_ptr);

#endif /* _TCPIP_HEADER_INCLUDED_ */
