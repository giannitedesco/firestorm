/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <pkt/tcp.h>
#include <pkt/smtp.h>
#include <f_stream.h>

#include <limits.h>
#include <ctype.h>

#if 0
#define dmesg mesg
#else
#define dmesg(x...) do { } while(0);
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

	while(isspace(*ptr))
		ptr++;

	r->code = code;
	r->msg.v_ptr = ptr;
	r->msg.v_len = end - ptr;

	return 1;
}

static void do_response(struct smtp_flow *f, struct ro_vec *v)
{
	struct smtp_response r;

	switch(f->state) {
	case SMTP_STATE_CMD:
	case SMTP_STATE_DATA:
		return;
	default:
		break;
	}

	if ( !parse_response(&r, v) ) {
		mesg(M_ERR, "smtp: parse error: %.*s", v->v_len, v->v_ptr);
		return;
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
}

static void parse_request(struct smtp_request *r, struct ro_vec *v)
{
}

static void do_request(struct smtp_flow *f, struct ro_vec *v)
{
	switch(f->state) {
	case SMTP_STATE_CMD:
		dmesg(M_DEBUG, ">>> %.*s", v->v_len, v->v_ptr);
		f->state = SMTP_STATE_RESP;
		break;
	case SMTP_STATE_DATA:
		if ( v->v_len == 1 && v->v_ptr[0] == '.' )
			f->state = SMTP_STATE_RESP;
		break;
	default:
		return;
	}
}

static int smtp_line(struct smtp_flow *f, unsigned int chan,
			const uint8_t *ptr, size_t len)
{
	struct ro_vec vec;

	assert(f->state < SMTP_STATE_MAX);

	vec.v_ptr = ptr;
	vec.v_len = len;

	switch(chan) {
	case TCP_CHAN_TO_CLIENT:
		do_response(f, &vec);
		break;
	case TCP_CHAN_TO_SERVER:
		do_request(f, &vec);
		break;
	}

	return 1;
}

static ssize_t smtp_push(struct _stream *s, unsigned int chan,
		struct ro_vec *vec, size_t numv, size_t bytes)
{
	struct smtp_flow *f;
	const uint8_t *buf;
	ssize_t ret;
	size_t sz;
	int do_free;

	f = s->s_flow;

	ret = stream_push_line(vec, numv, bytes, &sz);
	if ( ret <= 0 )
		return ret;
	
	if ( sz > vec[0].v_len ) {
		buf = malloc(sz);
		s->s_reasm(s, (uint8_t *)buf, sz);
		do_free = 1;
	}else{
		buf = vec[0].v_ptr;
		do_free = 0;
	}

	if ( !smtp_line(f, chan, buf, sz) )
		ret = 0;

	if ( do_free )
		free((void *)buf);

	return ret;
}

static int flow_init(void *fptr)
{
	struct smtp_flow *f = fptr;
	f->state = SMTP_STATE_INIT;
	return 1;
}

static void flow_fini(void *fptr)
{
}


struct _sproto sp_smtp = {
	.sp_label = "smtp",
	.sp_push = smtp_push,
	.sp_flow_sz = sizeof(struct smtp_flow),
	.sp_flow_init = flow_init,
	.sp_flow_fini = flow_fini,
};

static void __attribute__((constructor)) smtp_ctor(void)
{
	sproto_add(&sp_smtp);
	sproto_register(&sp_smtp, SNS_TCP, sys_be16(25));
}
