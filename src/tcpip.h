/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _TCPIP_HEADER_INCLUDED_
#define _TCPIP_HEADER_INCLUDED_

extern struct _decoder _ipv4_decoder;
extern struct _proto _p_tcpstream;
extern struct _flow_tracker _ipv4_ipdefrag;
extern struct _flow_tracker _ipv4_tcpflow;

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
	uint8_t reasm_flags;
	uint8_t reasm_shutdown;
	uint8_t reasm_fin_sent;

	/* TCP state: host byte order */
	struct tcp_state c_wnd;
	struct tcp_state *s_wnd;

	struct list_head lru;
};

int _ipdefrag_ctor(void);
void _ipdefrag_dtor(void);
void _ipdefrag_track(pkt_t pkt, dcb_t dcb_ptr);

int _tcpflow_ctor(void);
void _tcpflow_dtor(void);
void _tcpflow_track(pkt_t pkt, dcb_t dcb_ptr);

void *_tcp_alloc(struct tcp_session *s, objcache_t o, int reasm);

int _tcp_reasm_ctor(mempool_t pool);
void _tcp_reasm_dtor(void);

void _tcp_reasm_init(struct tcp_session *s, uint8_t to_server,
			uint32_t seq, uint32_t len, const uint8_t *buf);
void _tcp_reasm_data(struct tcp_session *s, uint8_t to_server,
			uint32_t seq, uint32_t len, const uint8_t *buf);
void _tcp_reasm_ack(struct tcp_session *s, uint8_t to_server);
void _tcp_reasm_shutdown(struct tcp_session *s, uint8_t to_server);
void _tcp_reasm_fin_sent(struct tcp_session *s, uint8_t to_server);
void _tcp_reasm_abort(struct tcp_session *s, int rst);
size_t _tcp_reasm_buffer_size(struct tcp_session *s);

struct tcp_app *_tcp_app_find_by_dport(uint16_t dport);
size_t _tcp_app_max_dcb(void);

extern struct _proto _p_tcpstream;
#endif /* _TCPIP_HEADER_INCLUDED_ */
