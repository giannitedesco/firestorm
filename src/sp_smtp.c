/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <p_tcp.h>
#include <p_smtp.h>

#include <limits.h>
#include <ctype.h>

#if 0
#define dmesg mesg
#define dhex_dump hex_dump
#else
#define dmesg(x...) do { } while(0);
#define dhex_dump(x...) do { } while(0);
#endif

static struct _proto p_smtp_req = {
	.p_label = "smtp_request",
	.p_dcb_sz = sizeof(struct smtp_request_dcb),
};

static struct _proto p_smtp_resp = {
	.p_label = "smtp_response",
	.p_dcb_sz = sizeof(struct smtp_response_dcb),
};

static struct _proto p_smtp_cont = {
	.p_label = "smtp_cont",
	.p_dcb_sz = sizeof(struct smtp_cont_dcb),
};

static int parse_response(struct smtp_response_dcb *r, struct ro_vec *v)
{
	const uint8_t *end = v->v_ptr + v->v_len;
	const uint8_t *ptr = v->v_ptr;
	unsigned int code;
	size_t code_len;

	code_len = vtouint(v, &code);
	if ( code_len != 3 )
		return 0;

	ptr += 3;
	if ( '-' == *ptr ) {
		r->flags = SMTP_RESP_MULTI;
		ptr++;
	}

	while(ptr < end && isspace(*ptr))
		ptr++;

	r->code = code;
	r->msg.v_ptr = ptr;
	r->msg.v_len = end - ptr;

	return 1;
}

static int decode_response(struct _pkt *pkt, struct ro_vec *v)
{
	struct smtp_response_dcb *r;

	r = (struct smtp_response_dcb *)decode_layer0(pkt, &p_smtp_resp);
	if ( NULL == r )
		return 0;

	if ( !parse_response(r, v) ) {
		mesg(M_ERR, "smtp: parse error: %.*s", v->v_len, v->v_ptr);
		return 1;
	}

	return 1;
}

struct smtp_cmd {
	struct ro_vec cmd;
	int (*fn)(struct _pkt *pkt, struct smtp_request_dcb *r);
};

static const struct smtp_cmd cmds[] = {
	{ .cmd = {.v_ptr = (uint8_t *)"AUTH", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"DATA", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"EHLO", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"EXPN", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"HELO", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"HELP", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"MAIL", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"NOOP", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"QUIT", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"RCPT", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"RSET", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"VRFY", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"DEBUG", .v_len = 5}, .fn = NULL },
};

static int dispatch_req(struct _pkt *pkt, struct smtp_request_dcb *r,
			 struct ro_vec *v)
{
	struct smtp_request_dcb *dcb;
	const struct smtp_cmd *c;
	unsigned int n;

	/* TODO: may want special dcb for parsing senders/recipients etc */
	for(n = sizeof(cmds)/sizeof(*cmds), c = cmds; n; ) {
		unsigned int i;
		int ret;

		i = (n / 2);
		ret = vcasecmp(&r->cmd, &c[i].cmd);
		if ( ret < 0 ) {
			n = i;
		}else if ( ret > 0 ) {
			c = c + (i + 1);
			n = n - (i + 1);
		}else{
			if ( c[i].fn )
				return c[i].fn(pkt, r);
			break;
		}
	}

	/* generic cmd/string dcb */
	dcb = (struct smtp_request_dcb *)decode_layer0(pkt, &p_smtp_req);
	if ( NULL == dcb )
		return 0;

	dcb->cmd = r->cmd;
	dcb->str = r->str;

	return 1;
}

static int decode_request(struct _pkt *pkt, struct ro_vec *v)
{
	const struct tcpstream_dcb *stream;
	struct smtp_request_dcb r;
	const uint8_t *ptr, *end;

	stream = (const struct tcpstream_dcb *)pkt->pkt_dcb;

	r.cmd.v_ptr = v->v_ptr;
	r.cmd.v_len = 0;

	for(ptr = v->v_ptr, end = v->v_ptr + v->v_len; ptr < end; ptr++) {
		if ( isspace(*ptr) )
			break;
		r.cmd.v_len++;
	}
	for(; ptr < end && isspace(*ptr); ptr++)
		/* nothing */;

	r.str.v_len = end - ptr;
	r.str.v_ptr = (r.str.v_len) ? ptr : NULL;

	return dispatch_req(pkt, &r, v);
}

static int decode_content(struct _pkt *pkt, struct ro_vec *v)
{
	struct smtp_cont_dcb *dcb;

	dcb = (struct smtp_cont_dcb *)decode_layer0(pkt, &p_smtp_cont);
	if ( NULL == dcb )
		return 0;

	dcb->content = *v;
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

static void smtp_decode(struct _pkt *pkt)
{
	const struct smtp_flow *f;
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
	case SMTP_STATE_INIT:
	case SMTP_STATE_RESP:
		assert(tcp->chan == TCP_CHAN_TO_CLIENT);
		ret = decode_response(pkt, &line);
		break;
	case SMTP_STATE_CMD:
		assert(tcp->chan == TCP_CHAN_TO_SERVER);
		ret = decode_request(pkt, &line);
		break;
	case SMTP_STATE_DATA:
		assert(tcp->chan == TCP_CHAN_TO_SERVER);
		ret = decode_content(pkt, &line);
		break;
	default:
		mesg(M_CRIT, "smtp: corrupt flow");
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
	struct smtp_flow *f;

	tcp = (struct tcpstream_dcb *)pkt->pkt_dcb;
	dcb = tcp->dcb.dcb_next;
	f = tcp_sesh_get_flow(sesh);

	assert(dcb->dcb_proto == &p_smtp_req ||
		dcb->dcb_proto == &p_smtp_resp ||
		dcb->dcb_proto == &p_smtp_cont);

	if ( dcb->dcb_proto == &p_smtp_req ) {
		struct smtp_request_dcb *r;
		r = (struct smtp_request_dcb *)dcb;

		f->state = SMTP_STATE_RESP;

		dmesg(M_DEBUG, ">>> %.*s %.*s",
			r->cmd.v_len, r->cmd.v_ptr,
			r->str.v_len, r->str.v_ptr);
	}else if ( dcb->dcb_proto == &p_smtp_resp ) {
		struct smtp_response_dcb *r;
		r = (struct smtp_response_dcb *)dcb;

		if ( 0 == (r->flags & SMTP_RESP_MULTI) ) {
			if ( r->code == 354 ) {
				f->state = SMTP_STATE_DATA;
			}else{
				f->state = SMTP_STATE_CMD;
			}
		}

		dmesg(M_DEBUG, "<<< %3u%c%.*s", r->code,
			(r->flags & SMTP_RESP_MULTI) ? '-' : ' ',
			r->msg.v_len, r->msg.v_ptr);
	}else if ( dcb->dcb_proto == &p_smtp_cont ) {
		struct smtp_cont_dcb *r;
		r = (struct smtp_cont_dcb *)dcb;
		if ( r->content.v_len == 1 && r->content.v_ptr[0] == '.' )
			f->state = SMTP_STATE_RESP;
		dmesg(M_DEBUG, ">>> DATA: %.*s",
			r->content.v_len, r->content.v_ptr);
	}

	switch(f->state) {
	case SMTP_STATE_CMD:
	case SMTP_STATE_DATA:
		tcp_sesh_wait(sesh, TCP_CHAN_TO_SERVER);
		break;
	case SMTP_STATE_INIT:
	case SMTP_STATE_RESP:
		tcp_sesh_wait(sesh, TCP_CHAN_TO_CLIENT);
		break;
	default:
		assert(0);
		break;
	}
}

static int push(tcp_sesh_t sesh, tcp_chan_t chan)
{
	const struct smtp_flow *f;
	const struct ro_vec *vec;
	size_t numv, bytes, llen, b;
	tcp_chan_t c;

	f = tcp_sesh_get_flow(sesh);
	switch(f->state) {
	case SMTP_STATE_RESP:
	case SMTP_STATE_INIT:
		c = TCP_CHAN_TO_CLIENT;
		break;
	case SMTP_STATE_CMD:
	case SMTP_STATE_DATA:
		c = TCP_CHAN_TO_SERVER;
		break;
	default:
		mesg(M_CRIT, "smtp: corrupt flow");
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

static objcache_t flow_cache;

static int shutdown(tcp_sesh_t sesh, tcp_chan_t chan)
{
	return 1;
}

static int init(tcp_sesh_t sesh)
{
	struct smtp_flow *f;

	f = objcache_alloc(flow_cache);
	if ( NULL == f )
		return 0;

	dmesg(M_DEBUG, "smtp_init");
	f->state = SMTP_STATE_INIT;
	f->flags = 0;

	tcp_sesh_set_flow(sesh, f);
	tcp_sesh_wait(sesh, TCP_CHAN_TO_CLIENT);
	return 1;
}

static void fini(tcp_sesh_t sesh)
{
	struct smtp_flow *f;

	f = tcp_sesh_get_flow(sesh);
	if ( NULL == f )
		return;

	dmesg(M_DEBUG, "smtp_fini");
	objcache_free2(flow_cache, f);
}

static int smtp_flow_ctor(void)
{
	flow_cache = objcache_init(NULL, "smtp_flows",
					sizeof(struct smtp_flow));
	if ( NULL == flow_cache )
		return 0;

	return 1;
}

static void smtp_flow_dtor(void)
{
	objcache_fini(flow_cache);
}

static struct _decoder smtp_decoder = {
	.d_decode = smtp_decode,
	.d_flow_ctor = smtp_flow_ctor,
	.d_flow_dtor = smtp_flow_dtor,
	.d_label = "smtp",
};

static struct tcp_app smtp_app = {
	.a_push = push,
	.a_state_update = state_update,
	.a_shutdown = shutdown,
	.a_init = init,
	.a_fini = fini,
	.a_decode = &smtp_decoder,
	.a_label = "smtp",
};

static void __attribute__((constructor)) smtp_ctor(void)
{
	decoder_add(&smtp_decoder);
	proto_add(&smtp_decoder, &p_smtp_req);
	proto_add(&smtp_decoder, &p_smtp_resp);
	proto_add(&smtp_decoder, &p_smtp_cont);

	tcp_app_register(&smtp_app);
	tcp_app_register_dport(&smtp_app, 25);
}
