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

int _ipdefrag_ctor(void);
void _ipdefrag_dtor(void);
void _ipdefrag_track(pkt_t pkt, dcb_t dcb_ptr);

int _tcpflow_ctor(void);
void _tcpflow_dtor(void);
void _tcpflow_track(pkt_t pkt, dcb_t dcb_ptr);

void *_tcp_alloc(struct tcp_session *s, objcache_t o, int reasm);

int _tcp_reasm_ctor(mempool_t pool);
void _tcp_reasm_dtor(void);
int _tcp_reasm_init(struct tcp_session *s);
int _tcp_reasm_inject(struct tcp_session *s, unsigned int chan,
			uint32_t seq, uint32_t len, const uint8_t *buf);
int _tcp_stream_push(struct tcp_session *s, unsigned int chan, uint32_t ack);
void _tcp_reasm_free(struct tcp_session *s, int abort);

void _tcpstream_decode(struct _pkt *pkt);

#endif /* _TCPIP_HEADER_INCLUDED_ */
