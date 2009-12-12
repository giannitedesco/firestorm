/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _P_TCP_HEADER_INCLUDED_
#define _P_TCP_HEADER_INCLUDED_

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

	struct tcp_sbuf *reasm;
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
	/* Timeout list */
	struct list_head tmo;
	uint32_t expire;

	/* Hash table collision chaining */
	struct tcp_session **hash_pprev, *hash_next;

	/* TCP state: network byte order */
	uint32_t c_addr, s_addr;
	uint16_t c_port, s_port;

	uint8_t state;
	uint8_t reasm;
	uint16_t _pad1;

	/* TCP state: host byte order */
	struct tcp_state c_wnd;
	struct tcp_state *s_wnd;

	const struct _sdecode *proto;
	void *flow;

	struct list_head lru;
};

#define TCP_CHAN_TO_CLIENT	0
#define TCP_CHAN_TO_SERVER	1

struct tcpstream_dcb {
	struct _dcb dcb;
	struct tcp_session *s;
	struct tcp_sbuf *sbuf;
	/** realloc semantics */
	const uint8_t *(*reasm)(struct tcp_sbuf *s, size_t len);
	schan_t chan;
};

extern struct _decoder _tcpstream_decoder;

#endif /* _P_TCP_HEADER_INCLUDED_ */
