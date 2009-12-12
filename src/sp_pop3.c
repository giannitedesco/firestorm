/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <f_stream.h>
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

static int parse_response(struct pop3_response *r, struct ro_vec *v)
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

static int do_response(struct _pkt *pkt, struct ro_vec *v)
{
	const struct tcpstream_dcb *dcb;
	struct pop3_flow *f;
	struct pop3_response r;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	switch(f->state) {
	case POP3_STATE_INIT:
	case POP3_STATE_RESP:
	case POP3_STATE_RESP_DATA:
		break;
	case POP3_STATE_DATA:
		if ( v->v_len == 1 && v->v_ptr[0] == '.' ) {
			f->state = POP3_STATE_CMD;
		}
		return 1;
	default:
		return 1;
	}

	if ( !parse_response(&r, v) ) {
		mesg(M_ERR, "pop3: response: %.*s", v->v_len, v->v_ptr);
		return 1;
	}

	//dmesg(M_DEBUG, "<<< %s %.*s",
	//	(r.ok) ? "OK" : "ERR",
	//	r.str.v_len, r.str.v_ptr);

	if ( f->state == POP3_STATE_RESP_DATA && r.ok ) {
		f->state = POP3_STATE_DATA;
	}else{
		f->state = POP3_STATE_CMD;
	}

	return 1;
}

struct pop3_cmd {
	struct ro_vec cmd;
	void(*fn)(struct _pkt *pkt, struct pop3_request *r);
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

static void dispatch_req(struct _pkt *pkt, struct pop3_request *r)
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
				c[i].fn(pkt, r);
			break;
		}
	}

	//dmesg(M_DEBUG, ">>> %.*s %.*s",
	//	r->cmd.v_len, r->cmd.v_ptr,
	//	r->str.v_len, r->str.v_ptr);
}

static int parse_request(struct _pkt *pkt, struct pop3_request *r,
				struct ro_vec *v)
{
	const struct tcpstream_dcb *dcb;
	struct pop3_flow *f;
	const uint8_t *ptr, *end;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	if ( v->v_len < 4 )
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

	dispatch_req(pkt, r);
	return 1;
}

static int do_request(struct _pkt *pkt, struct ro_vec *v)
{
	const struct tcpstream_dcb *dcb;
	struct pop3_flow *f;
	struct pop3_request r;
	struct ro_vec data = {
		.v_ptr = (uint8_t *)"RETR",
		.v_len = 4,
	};

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	if ( f->state != POP3_STATE_CMD )
		return 0;

	if ( !parse_request(pkt, &r, v) ) {
		mesg(M_ERR, "pop3: request: %.*s", v->v_len, v->v_ptr);
		return 1;
	}

	if ( vcasecmp(&data, &r.cmd) ) {
		f->state = POP3_STATE_RESP;
	}else{
		f->state = POP3_STATE_RESP_DATA;
	}
	return 1;
}

static int pop3_line(struct _pkt *pkt, const uint8_t *ptr, size_t len)
{
	const struct tcpstream_dcb *dcb;
	struct pop3_flow *f;
	struct ro_vec vec;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	assert(f->state < POP3_STATE_MAX);

	vec.v_ptr = ptr;
	vec.v_len = len;

	switch(dcb->chan) {
	case TCP_CHAN_TO_CLIENT:
		return do_response(pkt, &vec);
	case TCP_CHAN_TO_SERVER:
		return do_request(pkt, &vec);
	default:
		break;
	}

	return 1;
}

static ssize_t pop3_push(struct _pkt *pkt, struct ro_vec *vec, size_t numv,
			 size_t bytes)
{
	const struct tcpstream_dcb *dcb;
	struct pop3_flow *f;
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

	if ( !pop3_line(pkt, buf, sz) )
		ret = 0;

	return ret;
}

static int flow_init(void *priv)
{
	struct tcp_session *s = priv;
	struct pop3_flow *f = s->flow;
	f->state = POP3_STATE_INIT;
	return 1;
}

static void flow_fini(void *priv)
{
}


static struct _sdecode sd_pop3 = {
	.sd_label = "pop3",
	.sd_push = pop3_push,
	.sd_flow_init = flow_init,
	.sd_flow_fini = flow_fini,
	.sd_flow_sz = sizeof(struct pop3_flow),
	.sd_max_msg = 1024,
};

static void __attribute__((constructor)) pop3_ctor(void)
{
	sdecode_add(&sd_pop3);
	sdecode_register(&sd_pop3, SNS_TCP, sys_be16(110));
}
