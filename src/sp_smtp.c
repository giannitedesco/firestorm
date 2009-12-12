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

static int parse_response(struct smtp_response *r, struct ro_vec *v)
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

static int do_response(struct _pkt *pkt, struct ro_vec *v)
{
	const struct tcpstream_dcb *dcb;
	struct smtp_flow *f;
	struct smtp_response r;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	switch(f->state) {
	case SMTP_STATE_CMD:
	case SMTP_STATE_DATA:
		return 0;
	default:
		break;
	}

	if ( !parse_response(&r, v) ) {
		mesg(M_ERR, "smtp: parse error: %.*s", v->v_len, v->v_ptr);
		return 1;
	}

	dmesg(M_DEBUG, "<<< %3u%c%.*s", r.code,
		(r.flags & SMTP_RESP_MULTI) ? '-' : ' ',
		r.msg.v_len, r.msg.v_ptr);

	if ( 0 == (r.flags & SMTP_RESP_MULTI) ) {
		if ( r.code == 354 )
			f->state = SMTP_STATE_DATA;
		else
			f->state = SMTP_STATE_CMD;
	}

	return 1;
}

struct smtp_cmd {
	struct ro_vec cmd;
	void(*fn)(struct _pkt *pkt, struct smtp_request *r);
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

static void dispatch_req(struct _pkt *pkt, struct smtp_request *r)
{
	const struct smtp_cmd *c;
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

	dmesg(M_DEBUG, ">>> %.*s %.*s",
		r->cmd.v_len, r->cmd.v_ptr,
		r->str.v_len, r->str.v_ptr);
}

static int parse_request(struct _pkt *pkt, struct ro_vec *v)
{
	const struct tcpstream_dcb *dcb;
	struct smtp_flow *f;
	struct smtp_request r;
	const uint8_t *ptr, *end;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	if ( v->v_len < 4 )
		return 0;

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

	dispatch_req(pkt, &r);
	return 1;
}

static int do_request(struct _pkt *pkt, struct ro_vec *v)
{
	const struct tcpstream_dcb *dcb;
	struct smtp_flow *f;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	switch(f->state) {
	case SMTP_STATE_CMD:
		if ( !parse_request(pkt, v) ) {
			mesg(M_ERR, "smtp: parse error: %.*s",
				v->v_len, v->v_ptr);
			return 1;
		}
		f->state = SMTP_STATE_RESP;
		break;
	case SMTP_STATE_DATA:
		if ( v->v_len == 1 && v->v_ptr[0] == '.' )
			f->state = SMTP_STATE_RESP;
		break;
	default:
		return 0;
	}

	return 1;
}

static int smtp_line(struct _pkt *pkt, const uint8_t *ptr, size_t len)
{
	const struct tcpstream_dcb *dcb;
	struct smtp_flow *f;
	struct ro_vec vec;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	assert(f->state < SMTP_STATE_MAX);

	vec.v_ptr = ptr;
	vec.v_len = len;

	switch(dcb->chan) {
	case TCP_CHAN_TO_CLIENT:
		return do_response(pkt, &vec);
	case TCP_CHAN_TO_SERVER:
		return do_request(pkt, &vec);
	}

	return 1;
}

static ssize_t smtp_push(struct _pkt *pkt, struct ro_vec *vec, size_t numv,
			 size_t bytes)
{
	const struct tcpstream_dcb *dcb;
	struct smtp_flow *f;
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

	if ( !smtp_line(pkt, buf, sz) )
		ret = 0;

	return ret;
}

static int flow_init(void *priv)
{
	struct tcp_session *s = priv;
	struct smtp_flow *f = s->flow;
	f->state = SMTP_STATE_INIT;
	return 1;
}

static void flow_fini(void *priv)
{
}

static struct _sdecode sd_smtp = {
	.sd_label = "smtp",
	.sd_push = smtp_push,
	.sd_flow_init = flow_init,
	.sd_flow_fini = flow_fini,
	.sd_flow_sz = sizeof(struct smtp_flow),
	.sd_max_msg = 1024,
};

static void __attribute__((constructor)) smtp_ctor(void)
{
	sdecode_add(&sd_smtp);
	sdecode_register(&sd_smtp, SNS_TCP, sys_be16(25));
}
