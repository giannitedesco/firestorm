/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _P_TCP_HEADER_INCLUDED_
#define _P_TCP_HEADER_INCLUDED_

#define TCP_CHAN_TO_SERVER	(1<<0)
#define TCP_CHAN_TO_CLIENT	(1<<1)

typedef struct tcp_session *tcp_sesh_t;
typedef uint8_t tcp_chan_t;

struct tcpstream_dcb {
	struct _dcb dcb;
	tcp_sesh_t sesh;
	tcp_chan_t chan;
};

struct tcp_app {
	int (*a_push)(tcp_sesh_t sesh, tcp_chan_t chan);
	void (*a_state_update)(tcp_sesh_t sesh, tcp_chan_t chan, pkt_t pkt);
	int (*a_shutdown)(tcp_sesh_t sesh, tcp_chan_t chan);
	int (*a_init)(tcp_sesh_t sesh);
	void (*a_fini)(tcp_sesh_t sesh);
	struct _decoder *a_decode;
	size_t a_max_dcb;
	struct tcp_app *a_next;
	const char *a_label;
};

void tcp_app_register(struct tcp_app *app);
void tcp_app_register_dport(struct tcp_app *app, uint16_t dport);
/* TODO: register content/initiator-chan heuristics for proto detection */

extern struct _decoder _tcpstream_decoder;

#endif /* _P_TCP_HEADER_INCLUDED_ */
