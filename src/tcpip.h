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

/* Reassembly buffer */
struct tcp_sbuf {
	struct tcpr_node *root; /* root node of rbtree */
	uint32_t begin; /* sequence number of first byte (not always rcv_nxt) */
	uint32_t reasm_begin; /* sequence number of first unswallowed byte */
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

	struct tcp_sbuf reasm;
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

	//struct _proto *proto;
	//void *flow;

	/* expiry time */
	timestamp_t expire;
};

#define TCPHASH 509 /* prime */
struct tcpflow {
	/* flow hash */
	struct list_head lru;
	obj_cache_t session_cache;
	struct tcp_session *hash[TCPHASH];
	struct list_head syn1;

	/* stats */
	unsigned int num_packets;
	unsigned int state_errs;
	unsigned int num_csum_errs;
	unsigned int num_ttl_errs;
	unsigned int num_timeouts;
	unsigned int num_active;
	unsigned int max_active;
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

int _ipdefrag_ctor(struct ipdefrag *ipd, memchunk_t mc);
void _ipdefrag_dtor(struct ipdefrag *ipd, memchunk_t mc);
void _ipdefrag_track(flow_state_t s, pkt_t pkt, dcb_t dcb_ptr);

int _tcpflow_ctor(struct tcpflow *ipd, memchunk_t mc);
void _tcpflow_dtor(struct tcpflow *ipd, memchunk_t mc);
void _tcpflow_track(flow_state_t sptr, pkt_t pkt, dcb_t dcb_ptr);

void _tcp_reasm_inject(struct tcp_sbuf *s, uint32_t seq,
			uint32_t len, const void *buf);
void _tcp_reasm_free(struct tcp_sbuf *s);
uint8_t *_tcp_reassemble(struct tcp_sbuf *s, uint32_t ack, size_t *len);

#endif /* _TCPIP_HEADER_INCLUDED_ */
