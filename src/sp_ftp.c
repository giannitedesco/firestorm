/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <p_tcp.h>

#include <limits.h>
#include <ctype.h>

#define FTP_STATE_INIT 		0
#define FTP_STATE_CMD 		1
#define FTP_STATE_RESP 		2
#define FTP_STATE_MAX 		3
struct ftp_flow {
	uint8_t state;
};

static int ftp_line(struct _pkt *pkt, const uint8_t *ptr, size_t len)
{
	const struct tcpstream_dcb *dcb;
	struct ftp_flow *f;
	struct ro_vec vec;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	assert(f->state < FTP_STATE_MAX);

	vec.v_ptr = ptr;
	vec.v_len = len;

	switch(dcb->chan) {
	case TCP_CHAN_TO_CLIENT:
		break;
	case TCP_CHAN_TO_SERVER:
		break;
	default:
		break;
	}

	return 1;
}

static ssize_t ftp_push(struct _pkt *pkt, struct ro_vec *vec, size_t numv,
			size_t bytes)
{
	const struct tcpstream_dcb *dcb;
	struct ftp_flow *f;
	const uint8_t *buf;
	ssize_t ret;
	size_t sz;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	ret = stream_push_line(vec, numv, bytes, &sz);
	if ( ret <= 0 )
		return ret;
	
	if ( sz > vec[0].v_len ) {
		buf = dcb->reasm(dcb->sbuf, sz);
	}else{
		buf = vec[0].v_ptr;
	}

	if ( !ftp_line(pkt, buf, sz) )
		ret = 0;

	return ret;
}

static int flow_init(void *priv)
{
	struct tcp_session *s = priv;
	struct ftp_flow *f = s->flow;
	f->state = FTP_STATE_INIT;
	return 1;
}

static void flow_fini(void *priv)
{
}


static struct _sdecode sd_ftp = {
	.sd_label = "ftp",
	.sd_push = ftp_push,
	.sd_flow_init = flow_init,
	.sd_flow_fini = flow_fini,
	.sd_flow_sz = sizeof(struct ftp_flow),
	.sd_max_msg = 1024,
};

static void __attribute__((constructor)) ftp_ctor(void)
{
	sdecode_add(&sd_ftp);
	sdecode_register(&sd_ftp, SNS_TCP, sys_be16(21));
}
