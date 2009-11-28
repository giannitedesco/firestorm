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

struct tcp_rbuf {
	/** List entry */
	struct list_head	r_list;
	/** sequence number of first byte of buffer */
	uint32_t		r_seq;
	/** buffer base pointer */
	uint8_t			*r_base;
};

struct tcp_gap {
	uint32_t 		g_begin;
	uint32_t 		g_end;
};

/* Reassembly buffer */
#define TCP_REASM_MAX_GAPS	12
struct tcp_sbuf {
	/** begin seq for buffer purposes */
	uint32_t		s_begin;
	/** Sequence of first byte not reassembled */
	uint32_t		s_reasm_begin;
	/** Sequence number of last byte */
	uint32_t		s_end;
	/** Buffer list */
	struct list_head	s_bufs;
	/** last contiguous buffer */
	struct tcp_rbuf		*s_contig;
	/** sequence number of last contig byte */
	uint32_t 		s_contig_seq;
	/** number of gaps in reassembly */
	unsigned int		s_num_gaps;
	/** array of gap descriptors */
	struct tcp_gap		*s_gap[TCP_REASM_MAX_GAPS];
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
	uint32_t	snd_wnd; /* window size */
	uint32_t	snd_wl1; /* seq for last wup */
	uint32_t	snd_wl2; /* ack for last wup */

	uint32_t	ts_recent; /* a recent timestamp */
	uint32_t	ts_recent_stamp; /* local time on it */

	struct tcp_sbuf reasm;
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
	struct list_head list;

	/* Hash table collision chaining */
	struct tcp_session **hash_pprev, *hash_next;

	/* TCP state: network byte order */
	uint32_t c_addr, s_addr;
	uint16_t c_port, s_port;

	uint8_t state;
	uint8_t _pad0;
	uint16_t _pad1;

	/* TCP state: host byte order */
	struct tcp_state c_wnd;
	struct tcp_state *s_wnd;

	uint32_t expire;
};

#define TCPHASH 509 /* prime */
struct tcpflow {
	/* flow hash */
	struct tcp_session *hash[TCPHASH];

	/* memory caches */
	obj_cache_t session_cache;
	obj_cache_t sstate_cache;
	obj_cache_t rbuf_cache;
	obj_cache_t data_cache;
	obj_cache_t gap_cache;

	/* timeout lists */
	struct list_head lru;
	struct list_head tmo_msl;

	/* stats */
	unsigned int num_active;
	unsigned int max_active;
	unsigned int num_segments;
	unsigned int state_errs;

	unsigned int num_csum_errs;
	unsigned int num_ttl_errs;
	unsigned int num_timeouts;

	unsigned int max_gaps;
	unsigned int num_reasm;
	unsigned int reasm_bytes;
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

int _tcpflow_ctor(struct tcpflow *tf);
void _tcpflow_dtor(struct tcpflow *tf);
void _tcpflow_track(flow_state_t sptr, pkt_t pkt, dcb_t dcb_ptr);

void _tcp_reasm_init(struct tcpflow *tf, struct tcp_sbuf *s, uint32_t isn);
void _tcp_reasm_inject(struct tcpflow *tf, struct tcp_sbuf *s,
			uint32_t seq, uint32_t len,
			const uint8_t *buf);
void _tcp_reasm_free(struct tcpflow *tf, struct tcp_sbuf *s);
uint8_t *_tcp_reassemble(struct tcpflow *tf, struct tcp_sbuf *s,
			uint32_t ack, size_t *len);
int _tcp_reasm_ctor(struct tcpflow *tf);
void _tcp_reasm_dtor(struct tcpflow *tf);

#endif /* _TCPIP_HEADER_INCLUDED_ */
