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

#if 1
#define dmesg mesg
#define dhex_dump hex_dump
#else
#define dmesg(x...) do { } while(0);
#define dhex_dump(x...) do { } while(0);
#endif

#define FTP_STATE_INIT 		0
#define FTP_STATE_CMD 		1
#define FTP_STATE_RESP 		2
#define FTP_STATE_MAX 		3
struct ftp_flow {
	uint8_t state;
};

struct ftp_request_dcb {
	struct _dcb dcb;
	struct ro_vec cmd;
	struct ro_vec str;
};

struct ftp_response_dcb {
	struct _dcb dcb;
	struct ro_vec msg;
	uint16_t code;
};

static struct _proto p_ftp_req = {
	.p_label = "ftp_request",
	.p_dcb_sz = sizeof(struct ftp_request_dcb),
};

static struct _proto p_ftp_resp = {
	.p_label = "ftp_response",
	.p_dcb_sz = sizeof(struct ftp_response_dcb),
};

static int parse_response(struct ftp_response_dcb *r, struct ro_vec *v)
{
	const uint8_t *end = v->v_ptr + v->v_len;
	const uint8_t *ptr = v->v_ptr;
	unsigned int code;
	size_t code_len;

	code_len = vtouint(v, &code);
	if ( code_len != 3 )
		return 0;

	ptr += 3;
	while(ptr < end && isspace(*ptr))
		ptr++;

	r->code = code;
	r->msg.v_ptr = ptr;
	r->msg.v_len = end - ptr;

	return 1;
}

static int decode_request(struct _pkt *pkt, struct ro_vec *v)
{
	const struct tcpstream_dcb *stream;
	struct ftp_request_dcb *r;
	const uint8_t *ptr, *end;

	stream = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	r = (struct ftp_request_dcb *)decode_layer0(pkt, &p_ftp_req);
	if ( NULL == r )
		return 0;

	r->cmd.v_ptr = v->v_ptr;
	r->cmd.v_len = 0;

	for(ptr = v->v_ptr, end = v->v_ptr + v->v_len; ptr < end; ptr++) {
		if ( isspace(*ptr) )
			break;
		r->cmd.v_len++;
	}
	for(; ptr < end && isspace(*ptr); ptr++)
		/* nothing */;

	r->str.v_len = end - ptr;
	r->str.v_ptr = (r->str.v_len) ? ptr : NULL;

	return 1;
}

static int decode_response(struct _pkt *pkt, struct ro_vec *v)
{
	struct ftp_response_dcb *r;

	r = (struct ftp_response_dcb *)decode_layer0(pkt, &p_ftp_resp);
	if ( NULL == r )
		return 0;

	if ( !parse_response(r, v) ) {
		/* FIXME */
		mesg(M_ERR, "ftp: parse error: %.*s", v->v_len, v->v_ptr);
		return 1;
	}

	return 1;
}

static int parse_line(struct _pkt *pkt, struct ro_vec *vec)
{
	const uint8_t *ptr;

	vec->v_ptr = pkt->pkt_base;
	for(vec->v_len = 0, ptr = vec->v_ptr;
		*ptr != '\r' && *ptr != '\n';
		ptr++, vec->v_len++)
		/* o nothing */;
	
	return (*ptr == '\r' || *ptr == '\n');
}

static void ftp_decode(struct _pkt *pkt)
{
	const struct ftp_flow *f;
	const struct tcpstream_dcb *tcp;
	struct ro_vec line;
	int ret;

	tcp = (struct tcpstream_dcb *)pkt->pkt_dcb;
	f = tcp_sesh_get_flow(tcp->sesh);

	if ( !parse_line(pkt, &line) ) {
		pkt->pkt_len = 0;
		return;
	}

	switch(f->state) {
	case FTP_STATE_INIT:
	case FTP_STATE_RESP:
		assert(tcp->chan == TCP_CHAN_TO_CLIENT);
		ret = decode_response(pkt, &line);
		break;
	case FTP_STATE_CMD:
		assert(tcp->chan == TCP_CHAN_TO_SERVER);
		ret = decode_request(pkt, &line);
		break;
	default:
		mesg(M_CRIT, "ftp: corrupt flow");
		ret = 0;
		return;
	}

	if ( !ret )
		pkt->pkt_len = 0;
}

static void state_update(tcp_sesh_t sesh, tcp_chan_t chan, pkt_t pkt)
{
	const struct tcpstream_dcb *tcp;
	struct _dcb *dcb;
	struct ftp_flow *f;

	tcp = (struct tcpstream_dcb *)pkt->pkt_dcb;
	dcb = tcp->dcb.dcb_next;
	f = tcp_sesh_get_flow(sesh);

	assert(dcb->dcb_proto == &p_ftp_req ||
		dcb->dcb_proto == &p_ftp_resp);

	if ( dcb->dcb_proto == &p_ftp_req ) {
		struct ftp_request_dcb *r;
		r = (struct ftp_request_dcb *)dcb;

		f->state = FTP_STATE_RESP;

		dmesg(M_DEBUG, ">>> %.*s %.*s",
			r->cmd.v_len, r->cmd.v_ptr,
			r->str.v_len, r->str.v_ptr);
	}else if ( dcb->dcb_proto == &p_ftp_resp ) {
		struct ftp_response_dcb *r;
		r = (struct ftp_response_dcb *)dcb;

		if ( r->code != 150 )
			f->state = FTP_STATE_CMD;

		dmesg(M_DEBUG, "<<< %3u %.*s", r->code,
			r->msg.v_len, r->msg.v_ptr);
	}

	switch(f->state) {
	case FTP_STATE_CMD:
		tcp_sesh_wait(sesh, TCP_CHAN_TO_SERVER);
		break;
	case FTP_STATE_INIT:
	case FTP_STATE_RESP:
		tcp_sesh_wait(sesh, TCP_CHAN_TO_CLIENT);
		break;
	default:
		assert(0);
		break;
	}
}

static int push(tcp_sesh_t sesh, tcp_chan_t chan)
{
	const struct ftp_flow *f;
	const struct ro_vec *vec;
	size_t numv, bytes, llen, b;
	tcp_chan_t c;

	f = tcp_sesh_get_flow(sesh);
	switch(f->state) {
	case FTP_STATE_INIT:
	case FTP_STATE_RESP:
		c = TCP_CHAN_TO_CLIENT;
		break;
	case FTP_STATE_CMD:
		c = TCP_CHAN_TO_SERVER;
		break;
	default:
		mesg(M_CRIT, "ftp: corrupt flow");
		return -1;
	}

	assert(chan & c);

	vec = tcp_sesh_get_buf(sesh, c, &numv, &bytes);
	if ( NULL == vec )
		return 0;

	b = tcp_app_single_line(vec, numv, bytes, &llen);
	if ( 0 == b )
		return 0;

	tcp_sesh_inject(sesh, c, b);

	return 1;
}

static int shutdown(tcp_sesh_t sesh, tcp_chan_t chan)
{
	return 1;
}

static objcache_t flow_cache;

static int init(tcp_sesh_t sesh)
{
	struct ftp_flow *f;

	f = objcache_alloc(flow_cache);
	if ( NULL == f )
		return 0;

	dmesg(M_DEBUG, "ftp_init");
	f->state = FTP_STATE_INIT;

	tcp_sesh_set_flow(sesh, f);
	tcp_sesh_wait(sesh, TCP_CHAN_TO_CLIENT);
	return 1;
}

static void fini(tcp_sesh_t sesh)
{
	struct ftp_flow *f;

	f = tcp_sesh_get_flow(sesh);
	if ( NULL == f )
		return;

	dmesg(M_DEBUG, "ftp_fini");
	objcache_free2(flow_cache, f);
}

static int ftp_flow_ctor(void)
{
	flow_cache = objcache_init(NULL, "ftp_flows",
					sizeof(struct ftp_flow));
	if ( NULL == flow_cache )
		return 0;

	return 1;
}

static void ftp_flow_dtor(void)
{
	objcache_fini(flow_cache);
}

static struct _decoder ftp_decoder = {
	.d_decode = ftp_decode,
	.d_flow_ctor = ftp_flow_ctor,
	.d_flow_dtor = ftp_flow_dtor,
	.d_label = "ftp",
};

static struct tcp_app ftp_app = {
	.a_push = push,
	.a_state_update = state_update,
	.a_shutdown = shutdown,
	.a_init = init,
	.a_fini = fini,
	.a_decode = &ftp_decoder,
	.a_label = "ftp",
};

static void __attribute__((constructor)) ftp_ctor(void)
{
	decoder_add(&ftp_decoder);
	proto_add(&ftp_decoder, &p_ftp_req);
	proto_add(&ftp_decoder, &p_ftp_resp);

	tcp_app_register(&ftp_app);
	tcp_app_register_dport(&ftp_app, 21);
}
