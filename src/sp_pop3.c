/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <p_tcp.h>
#include <p_pop3.h>

#include <ctype.h>

#if 1
#define dmesg mesg
#define dhex_dump hex_dump
#else
#define dmesg(x...) do { } while(0);
#define dhex_dump(x...) do { } while(0);
#endif

static struct _proto p_pop3_req = {
	.p_label = "pop3_request",
	.p_dcb_sz = sizeof(struct pop3_request_dcb),
};

static struct _proto p_pop3_resp = {
	.p_label = "pop3_response",
	.p_dcb_sz = sizeof(struct pop3_response_dcb),
};

static struct _proto p_pop3_cont = {
	.p_label = "pop3_cont",
	.p_dcb_sz = sizeof(struct pop3_cont_dcb),
};

static int parse_response(struct pop3_response_dcb *r, struct ro_vec *v)
{
	const uint8_t *ptr, *end;

	if ( v->v_len < 1 )
		return 0;

	switch(v->v_ptr[0]) {
	case '+':
		r->ok = 1;
		break;
	case '-':
		r->ok = 0;
		break;
	default:
		return 0;
	}

	ptr = v->v_ptr + 1;
	end = v->v_ptr + v->v_len;
	while(ptr < end && !isspace(*ptr))
		ptr++;
	while(ptr < end && isspace(*ptr))
		ptr++;

	r->str.v_len = end - ptr;
	r->str.v_ptr = (r->str.v_len) ? ptr : NULL;
	return 1;
}

static int decode_response(struct _pkt *pkt, struct ro_vec *v)
{
	struct pop3_response_dcb *r;

	r = (struct pop3_response_dcb *)decode_layer(pkt, &p_pop3_resp);
	if ( NULL == r )
		return 0;

	if ( !parse_response(r, v) ) {
		mesg(M_ERR, "pop3: response: %.*s", v->v_len, v->v_ptr);
		return 0;
	}

	return 1;
}

static int decode_content(struct _pkt *pkt, struct ro_vec *v)
{
	struct pop3_cont_dcb *dcb;

	dcb = (struct pop3_cont_dcb *)decode_layer0(pkt, &p_pop3_cont);
	if ( NULL == dcb )
		return 0;

	dcb->content = *v;
	return 1;
}

struct pop3_cmd {
	struct ro_vec cmd;
	int (*fn)(struct _pkt *pkt, struct pop3_request_dcb *r);
};

static const struct pop3_cmd cmds[] = {
	{ .cmd = {.v_ptr = (uint8_t *)"TOP", .v_len = 3}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"APOP", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"DELE", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"LIST", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"NOOP", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"PASS", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"QUIT", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"RETR", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"RSET", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"STAT", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"UIDL", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"USER", .v_len = 4}, .fn = NULL },
};

static int dispatch_req(struct _pkt *pkt, struct pop3_request_dcb *r,
			 struct ro_vec *v)
{
	const struct pop3_cmd *c;
	unsigned int n;

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

	return 1;
}

static int parse_request(struct _pkt *pkt, struct pop3_request_dcb *r,
				struct ro_vec *v)
{
	const uint8_t *ptr, *end;

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

static int decode_request(struct _pkt *pkt, struct ro_vec *v)
{
	struct pop3_request_dcb *dcb;

	dcb = (struct pop3_request_dcb *)decode_layer0(pkt, &p_pop3_req);
	if ( NULL == dcb )
		return 0;

	if ( !parse_request(pkt, dcb, v) ) {
		mesg(M_ERR, "pop3: request: %.*s", v->v_len, v->v_ptr);
		return 1;
	}

	return dispatch_req(pkt, dcb, v);
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

static void pop3_decode(struct _pkt *pkt)
{
	const struct pop3_flow *f;
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
	case POP3_STATE_CMD:
		assert(tcp->chan == TCP_CHAN_TO_SERVER);
		ret = decode_request(pkt, &line);
		break;
	case POP3_STATE_INIT:
	case POP3_STATE_RESP:
	case POP3_STATE_RESP_DATA:
		assert(tcp->chan == TCP_CHAN_TO_CLIENT);
		ret = decode_response(pkt, &line);
		break;
	case POP3_STATE_DATA:
		assert(tcp->chan == TCP_CHAN_TO_CLIENT);
		ret = decode_content(pkt, &line);
		break;
	default:
		mesg(M_CRIT, "pop3: corrupt flow");
		ret = 0;
		break;
	}

	if ( !ret )
		pkt->pkt_len = 0;
}

static void state_update(tcp_sesh_t sesh, tcp_chan_t chan, pkt_t pkt)
{
	const struct tcpstream_dcb *tcp;
	struct _dcb *dcb;
	struct pop3_flow *f;

	tcp = (struct tcpstream_dcb *)pkt->pkt_dcb;
	dcb = tcp->dcb.dcb_next;
	f = tcp_sesh_get_flow(sesh);

	assert(dcb->dcb_proto == &p_pop3_req ||
		dcb->dcb_proto == &p_pop3_resp ||
		dcb->dcb_proto == &p_pop3_cont);

	if ( dcb->dcb_proto == &p_pop3_req ) {
		struct pop3_request_dcb *r;
		static const struct ro_vec retr = {
			.v_ptr = (uint8_t *)"RETR",
			.v_len = 4,
		};

		r = (struct pop3_request_dcb *)dcb;

		if ( vcasecmp(&retr, &r->cmd) ) {
			f->state = POP3_STATE_RESP;
		}else{
			f->state = POP3_STATE_RESP_DATA;
		}

		dmesg(M_DEBUG, ">>> %.*s %.*s",
			r->cmd.v_len, r->cmd.v_ptr,
			r->str.v_len, r->str.v_ptr);
	}else if ( dcb->dcb_proto == &p_pop3_resp ) {
		struct pop3_response_dcb *r;
		r = (struct pop3_response_dcb *)dcb;

		if ( f->state == POP3_STATE_RESP_DATA && r->ok ) {
			f->state = POP3_STATE_DATA;
		}else{
			f->state = POP3_STATE_CMD;
		}

		dmesg(M_DEBUG, "<<< %s %.*s",
			(r->ok) ? "OK" : "ERR",
			r->str.v_len, r->str.v_ptr);
	}else if ( dcb->dcb_proto == &p_pop3_cont ) {
		struct pop3_cont_dcb *r;
		r = (struct pop3_cont_dcb *)dcb;

		if ( r->content.v_len == 1 && r->content.v_ptr[0] == '.' )
			f->state = POP3_STATE_CMD;
	}

	switch(f->state) {
	case POP3_STATE_CMD:
		tcp_sesh_wait(sesh, TCP_CHAN_TO_SERVER);
		break;
	case POP3_STATE_INIT:
	case POP3_STATE_RESP:
	case POP3_STATE_RESP_DATA:
	case POP3_STATE_DATA:
		tcp_sesh_wait(sesh, TCP_CHAN_TO_CLIENT);
		break;
	default:
		mesg(M_CRIT, "pop3: corrupt flow");
		return;
	}
}

static int push(tcp_sesh_t sesh, tcp_chan_t chan)
{
	const struct pop3_flow *f;
	const struct ro_vec *vec;
	size_t numv, bytes, llen, b;
	tcp_chan_t c;

	f = tcp_sesh_get_flow(sesh);
	switch(f->state) {
	case POP3_STATE_CMD:
		c = TCP_CHAN_TO_SERVER;
		break;
	case POP3_STATE_INIT:
	case POP3_STATE_RESP:
	case POP3_STATE_RESP_DATA:
	case POP3_STATE_DATA:
		c = TCP_CHAN_TO_CLIENT;
		break;
	default:
		mesg(M_CRIT, "pop3: corrupt flow");
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
	struct pop3_flow *f;

	f = objcache_alloc(flow_cache);
	if ( NULL == f )
		return 0;

	dmesg(M_DEBUG, "pop3_init");
	f->state = POP3_STATE_INIT;

	tcp_sesh_set_flow(sesh, f);
	tcp_sesh_wait(sesh, TCP_CHAN_TO_CLIENT);
	return 1;
}

static void fini(tcp_sesh_t sesh)
{
	struct pop3_flow *f;

	f = tcp_sesh_get_flow(sesh);
	if ( NULL == f )
		return;

	dmesg(M_DEBUG, "pop3_fini");
	objcache_free2(flow_cache, f);
}

static int pop3_flow_ctor(void)
{
	flow_cache = objcache_init(NULL, "pop3_flows",
					sizeof(struct pop3_flow));
	if ( NULL == flow_cache )
		return 0;

	return 1;
}

static void pop3_flow_dtor(void)
{
	objcache_fini(flow_cache);
}

static struct _decoder pop3_decoder = {
	.d_decode = pop3_decode,
	.d_flow_ctor = pop3_flow_ctor,
	.d_flow_dtor = pop3_flow_dtor,
	.d_label = "pop3",
};

static struct tcp_app pop3_app = {
	.a_push = push,
	.a_state_update = state_update,
	.a_shutdown = shutdown,
	.a_init = init,
	.a_fini = fini,
	.a_decode = &pop3_decoder,
	.a_label = "pop3",
};

static void __attribute__((constructor)) pop3_ctor(void)
{
	decoder_add(&pop3_decoder);
	proto_add(&pop3_decoder, &p_pop3_req);
	proto_add(&pop3_decoder, &p_pop3_resp);
	proto_add(&pop3_decoder, &p_pop3_cont);

	tcp_app_register(&pop3_app);
	tcp_app_register_dport(&pop3_app, 110);
}
