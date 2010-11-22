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

extern struct _decoder _tcpstream_decoder;

#endif /* _P_TCP_HEADER_INCLUDED_ */
